package auth

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"sso/internal/domain/models"
	"sso/internal/lib/jwt"
	"sso/internal/lib/sl"
	"sso/internal/storage"
	"time"
)

type Auth struct {
	log          *slog.Logger
	userSaver    UserSaver
	userProvider UserProvider
	appProvider  AppProvider
	tokenTTL     time.Duration
}

type UserSaver interface {
	SaveUser(
		ctx context.Context,
		email string,
		passHash []byte,
	) (uid int64, err error)
}

type UserProvider interface {
	User(ctx context.Context, email string) (user models.User, err error)
	IsAdmin(ctx context.Context, userId int64) (isAdmin bool, err error)
}

type AppProvider interface {
	App(ctx context.Context, appId int64) (models.App, error)
}

var (
	ErrInvalidCredentials = errors.New("Invalid Credentials")
	ErrInvalidAppId       = errors.New("Invalid App ID")
	ErrUserExists         = errors.New("User already exists")
)

func New(
	log *slog.Logger,
	userProvider UserProvider,
	appProvider AppProvider,
	userSaver UserSaver,
	tokenTTL time.Duration,
) *Auth {
	return &Auth{
		userSaver:    userSaver,
		log:          log,
		userProvider: userProvider,
		appProvider:  appProvider,
		tokenTTL:     tokenTTL,
	}
}

func (a *Auth) Login(
	ctx context.Context,
	email, password string,
	appId int64,
) (string, error) {
	const op = "auth.Login"

	log := a.log.With(slog.String("op", op), slog.String("email", email), slog.String("password", password))

	user, err := a.userProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			a.log.Warn("User not found", sl.Err(err))

			return "", fmt.Errorf("%s:%w", op, ErrInvalidCredentials)
		}
		a.log.Error("Failed to get user", sl.Err(err))

		return "", fmt.Errorf("%s:%w", op, err)
	}
	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		a.log.Warn("Invalid credentials", sl.Err(err))
		return "", fmt.Errorf("%s:%w", op, ErrInvalidCredentials)
	}

	app, err := a.appProvider.App(ctx, appId)
	if err != nil {
		return "", fmt.Errorf("%s:%w", op, err)
	}

	log.Info("user logged")

	token, err := jwt.NewToken(user, app, a.tokenTTL)
	if err != nil {
		a.log.Error("Failed to create token", sl.Err(err))

		return "", fmt.Errorf("%s:%w", op, err)
	}

	return token, nil
}

func (a *Auth) RegisterNewUser(
	ctx context.Context,
	email, password string,
) (int64, error) {
	const op = "auth.RegisterNewUser"
	log := a.log.With(slog.String("op", op), slog.String("email", email))

	log.Info("register new user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to hash password", sl.Err(err))

		return 0, fmt.Errorf("%s: %w", op, ErrUserExists)
	}

	id, err := a.userSaver.SaveUser(ctx, email, passHash)
	if err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			a.log.Warn("User already exists", sl.Err(err))

			return 0, fmt.Errorf("%s: %w", op, err)
		}
		log.Error("failed to save user", sl.Err(err))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user registered successfully")

	return id, nil
}

func (a *Auth) IsAdmin(
	ctx context.Context,
	userId int64,
) (bool, error) {
	const op = "Auth.IsAmin"

	log := a.log.With(slog.String("op", op), slog.String("userId", fmt.Sprint(userId)))

	log.Info("checking if user is admin")

	isAdmin, err := a.userProvider.IsAdmin(ctx, userId)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			a.log.Warn("User not found", sl.Err(err))

			return false, fmt.Errorf("%s: %w", op, ErrInvalidAppId)
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("checked if user is admin", slog.Bool("isAdmin", isAdmin))
	return isAdmin, nil
}
