module Domain.Auth
  -- * Types
  ( Auth(..)
  , Email
  , mkEmail
  , rawEmail
  , Password
  , mkPassword
  , rawPassword
  , UserId
  , VerificationCode
  , SessionId
  , RegistrationError(..)
  , EmailVerificationError(..)
  , LoginError(..)

  -- * Ports
  , AuthRepo(..)
  , EmailVerificationNotif(..)
  , SessionRepo(..)

  -- * Use cases
  , register
  , verifyEmail
  , login
  , resolveSessionId
  , getUser
  ) where


import           ClassyPrelude
import           Data.Text
import           Domain.Validation
import           Text.Regex.PCRE.Heavy
import Control.Monad.Except

data Auth = Auth
  { authEmail    :: Email
  , authPassword :: Password
  } deriving (Show, Eq)

data RegistrationError = RegistrationErrorEmailTaken
  deriving (Show, Eq)
data EmailVerificationError = EmailVerificationErrorInvalidCode deriving (Show, Eq)

data EmailValidationError = EmailValidationErrorInvalidEmail deriving (Show, Eq)


data PasswordValidationErr
  = PasswordValidationErrLength Int
  | PasswordValidationErrMustContainUpperCase
  | PasswordValidationErrMustContainLowerCase
  | PasswordValidationErrMustContainNumber
  deriving (Show, Eq)

newtype Email = Email { emailRaw :: Text } deriving (Show, Ord, Eq)
newtype Password = Password { passwordRaw :: Text } deriving (Show, Ord, Eq)

rawEmail :: Email -> Text
rawEmail = emailRaw

rawPassword :: Password -> Text
rawPassword = passwordRaw

validEmailRegex = [re|^[A-Z0-9a-z._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,64}$|]
mkEmail :: Text -> Either [Text] Email
mkEmail = validate Email [ regexMatches validEmailRegex "Not a valid email" ]

mkPassword :: Text -> Either [Text] Password
mkPassword = validate Password
  [ lengthBetween 5 50 "Should between 5 and 50"
  , regexMatches [re|\d|] "Should contain number"
  , regexMatches [re|[A-Z]|] "Should contain uppercase letter"
  , regexMatches [re|[a-z]|] "Should contain lowercase letter"
  ]

type VerificationCode = Text

-- interface for authentication repository(storage)
class Monad m => AuthRepo m where
  addAuth :: Auth -> m (Either RegistrationError VerificationCode)
  setEmailAsVerified :: VerificationCode -> m (Either EmailVerificationError ())
  findUserByAuth :: Auth -> m (Maybe (UserId, Bool))
  findEmailFromUserId :: UserId -> m (Maybe Email)

class Monad m => SessionRepo m where
  newSession :: UserId -> m SessionId
  findUserIdBySessionId :: SessionId -> m (Maybe (UserId))

-- interface for email notification system
class Monad m => EmailVerificationNotif m where
  notifyEmailVerification :: Email -> VerificationCode -> m ()

register :: (AuthRepo m, EmailVerificationNotif m) => Auth -> m (Either RegistrationError ())
register auth = runExceptT $ do
  vCode <- ExceptT $ addAuth auth
  lift $ notifyEmailVerification (authEmail auth) vCode

verifyEmail :: (AuthRepo m) => VerificationCode -> m (Either EmailVerificationError ())
verifyEmail = setEmailAsVerified


instance EmailVerificationNotif IO where
  notifyEmailVerification email vcode =
    putStrLn $ "Notify " <> emailRaw email <> " - " <> vcode

type UserId = Int
type SessionId = Text

data LoginError = LoginErrorInvalidAuth
  | LoginErrorEmailNotVerified
  deriving (Show, Eq)

resolveSessionId :: SessionRepo m => SessionId -> m (Maybe UserId)
resolveSessionId = findUserIdBySessionId

getUser :: AuthRepo m => UserId -> m (Maybe Email)
getUser = findEmailFromUserId

login :: (AuthRepo m, SessionRepo m) => Auth -> m (Either LoginError SessionId)
login auth = runExceptT $ do
  result <- lift $ findUserByAuth auth
  case result of
    Nothing -> throwError LoginErrorInvalidAuth
    Just (_, False) -> throwError LoginErrorEmailNotVerified
    Just (userId, _) -> lift $ newSession userId
