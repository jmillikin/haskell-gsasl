{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE ForeignFunctionInterface #-}

-- Copyright (C) 2010 John Millikin <jmillikin@gmail.com>
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <http://www.gnu.org/licenses/>.

module Network.Protocol.SASL.GNU
	(
	-- * Library Information
	  headerVersion
	, libraryVersion
	, checkVersion
	
	-- * SASL Contexts
	, SASL
	, runSASL
	, setCallback
	, runCallback
	
	-- * Mechanisms
	, Mechanism (..)
	, clientMechanisms
	, clientSupports
	, clientSuggestMechanism
	, serverMechanisms
	, serverSupports
	
	-- * SASL Sessions
	, Session
	, runClient
	, runServer
	, mechanismName
	
	-- ** Session Properties
	, Property (..)
	, setProperty
	, getProperty
	, getPropertyFast
	
	-- ** Session IO
	, Progress (..)
	, step
	, step64
	, encode
	, decode
	
	-- ** Error handling
	, Error (..)
	, catch
	, handle
	, try
	, throw
	
	-- * Bundled codecs
	, toBase64
	, fromBase64
	, md5
	, sha1
	, hmacMD5
	, hmacSHA1
	, nonce
	, random
	) where

-- Imports {{{

import           Prelude hiding (catch)
import qualified Control.Exception as E
import           Control.Monad (when, unless)
import           Control.Monad.IO.Class (MonadIO, liftIO)
import qualified Control.Monad.Trans.Reader as R
import qualified Data.ByteString as B
import qualified Data.ByteString.Unsafe as B
import qualified Data.ByteString.Char8 as Char8
import           Data.Char (isDigit)
import           Data.String (IsString, fromString)
import           Data.Typeable (Typeable)
import qualified Foreign as F
import qualified Foreign.C as F
import           System.IO.Unsafe (unsafePerformIO)
import qualified Text.ParserCombinators.ReadP as P

-- }}}

-- Library Information {{{

-- | Which version of @gsasl.h@ this module was compiled against
headerVersion :: (Integer, Integer, Integer)
headerVersion = (major, minor, patch) where
	major = toInteger hsgsasl_VERSION_MAJOR
	minor = toInteger hsgsasl_VERSION_MINOR
	patch = toInteger hsgsasl_VERSION_PATCH

-- | Which version of @libgsasl.so@ is loaded
libraryVersion :: IO (Integer, Integer, Integer)
libraryVersion = io where
	parseVersion str = case P.readP_to_S parser str of
		[] -> Nothing
		((parsed, _):_) -> Just parsed
	parser = do
		majorS <- P.munch1 isDigit
		_ <- P.char '.'
		minorS <- P.munch1 isDigit
		_ <- P.char '.'
		patchS <- P.munch1 isDigit
		eof
		return (read majorS, read minorS, read patchS)
	io = do
		cstr <- gsasl_check_version F.nullPtr
		maybeStr <- F.maybePeek F.peekCString cstr
		return $ case maybeStr >>= parseVersion of
			Just version -> version
			Nothing -> error $ "Invalid version string: " ++ show maybeStr
	
	eof = do
		s <- P.look
		unless (null s) P.pfail

-- | Whether the header and library versions are compatible
checkVersion :: IO Bool
checkVersion = fmap (== 1) hsgsasl_check_version

-- }}}

-- SASL Contexts {{{

newtype Context = Context (F.Ptr Context)
newtype SASL a = SASL { unSASL :: R.ReaderT Context IO a }

instance Functor SASL where
	fmap f = SASL . fmap f . unSASL

instance Monad SASL where
	return = SASL . return
	(>>=) sasl f = SASL $ unSASL sasl >>= unSASL . f

instance MonadIO SASL where
	liftIO = SASL . liftIO

-- TODO: more instances

runSASL :: SASL a -> IO a
runSASL = withContext . R.runReaderT . unSASL

withContext :: (Context -> IO a) -> IO a
withContext = E.bracket newContext freeContext where
	newContext = F.alloca $ \pCtxt -> do
		gsasl_init pCtxt >>= checkRC
		Context `fmap` F.peek pCtxt
	freeContext (Context ctx) = do
		hook <- gsasl_callback_hook_get ctx
		gsasl_done ctx
		freeCallbackHook hook

getContext :: SASL (F.Ptr Context)
getContext = SASL $ do
	Context ptr <- R.ask
	return ptr

bracketSASL :: (F.Ptr Context -> IO a) -> (a -> IO b) -> (a -> IO c) -> SASL c
bracketSASL before after thing = do
	ctx <- getContext
	liftIO $ E.bracket (before ctx) after thing

-- }}}

-- Mechanisms {{{

newtype Mechanism = Mechanism B.ByteString
	deriving (Show, Eq)

instance IsString Mechanism where
	fromString = Mechanism . fromString

-- | A list of 'Mechanism's supported by the @libgsasl@ client.
clientMechanisms :: SASL [Mechanism]
clientMechanisms = bracketSASL io gsasl_free splitMechListPtr where
	io ctx = F.alloca $ \pStr -> do
		gsasl_client_mechlist ctx pStr >>= checkRC
		F.peek pStr

-- | Whether there is client-side support for a specified 'Mechanism'.
clientSupports :: Mechanism -> SASL Bool
clientSupports (Mechanism name) = do
	ctx <- getContext
	liftIO $ B.useAsCString name $ \pName -> do
		cres <- gsasl_client_support_p ctx pName
		return $ cres == 1

-- | Given a list of 'Mechanism's, suggest which to use (or 'Nothing' if
-- no supported 'Mechanism' is found).
clientSuggestMechanism :: [Mechanism] -> SASL (Maybe Mechanism)
clientSuggestMechanism mechs = do
	let bytes = B.intercalate (Char8.pack " ") [x | Mechanism x <- mechs]
	ctx <- getContext
	liftIO $ B.useAsCString bytes $ \pMechlist ->
		gsasl_client_suggest_mechanism ctx pMechlist >>=
		F.maybePeek (fmap Mechanism . B.packCString)

-- | A list of 'Mechanism's supported by the @libgsasl@ server.
serverMechanisms :: SASL [Mechanism]
serverMechanisms = bracketSASL io gsasl_free splitMechListPtr where
	io ctx = F.alloca $ \pStr -> do
		gsasl_server_mechlist ctx pStr >>= checkRC
		F.peek pStr

-- | Whether there is server-side support for a specified 'Mechanism'.
serverSupports :: Mechanism -> SASL Bool
serverSupports (Mechanism name) = do
	ctx <- getContext
	liftIO $ B.useAsCString name $ \pName -> do
		cres <- gsasl_server_support_p ctx pName
		return $ cres == 1

splitMechListPtr :: F.CString -> IO [Mechanism]
splitMechListPtr ptr = unfoldrM step' (ptr, ptr, 0, True) where
	step' (_, _, _, False) = return Nothing
	step' (p_0, p_i, i, _) = F.peek p_i >>= \chr -> let
		p_i' = F.plusPtr p_i 1
		peek continue = if i == 0
			then step' (p_i', p_i', 0, continue)
			else do
				bytes <- B.packCStringLen (p_0, i)
				return $ Just (Mechanism bytes, (p_i', p_i', 0, continue))
		in case chr of
			0x00 -> peek False
			0x20 -> peek True
			_    -> step' (p_0, p_i', i + 1, True)

-- }}}

-- SASL Sessions {{{

newtype SessionCtx = SessionCtx (F.Ptr SessionCtx)
newtype Session a = Session { unSession :: R.ReaderT SessionCtx IO a }

instance Functor Session where
	fmap f = Session . fmap f . unSession

instance Monad Session where
	return = Session . return
	(>>=) m f = Session $ unSession m >>= unSession . f

instance MonadIO Session where
	liftIO = Session . liftIO

type SessionProc = F.Ptr Context -> F.CString -> F.Ptr (F.Ptr SessionCtx) -> IO F.CInt

runSession :: SessionProc -> Mechanism -> Session a -> SASL (Either Error a)
runSession start (Mechanism mech) session = bracketSASL newSession freeSession io where
	newSession ctx =
		B.useAsCString mech $ \pMech ->
		F.alloca $ \pSessionCtx -> E.handle noSession $ do
		start ctx pMech pSessionCtx >>= checkRC
		fmap (Right . SessionCtx) $ F.peek pSessionCtx
	noSession (SASLException err) = return $ Left err
	
	freeSession (Left _) = return ()
	freeSession (Right (SessionCtx ptr)) = gsasl_finish ptr
	
	io (Left err) = return $ Left err
	io (Right sctx) = E.catch
		(fmap Right $ R.runReaderT (unSession session) sctx)
		(\(SASLException err) -> return $ Left err)

-- | Run a session using the @libgsasl@ client.
runClient :: Mechanism -> Session a -> SASL (Either Error a)
runClient = runSession gsasl_client_start

-- | Run a session using the @libgsasl@ server.
runServer :: Mechanism -> Session a -> SASL (Either Error a)
runServer = runSession gsasl_server_start

getSessionContext :: Session (F.Ptr SessionCtx)
getSessionContext = Session $ do
	SessionCtx sctx <- R.ask
	return sctx

-- | The name of the session's SASL mechanism.
mechanismName :: Session Mechanism
mechanismName = do
	sctx <- getSessionContext
	liftIO $ do
		cstr <- gsasl_mechanism_name sctx
		Mechanism `fmap` B.packCString cstr

bracketSession :: (F.Ptr SessionCtx -> IO a) -> (a -> IO b) -> (a -> IO c) -> Session c
bracketSession before after thing = do
	sctx <- getSessionContext
	liftIO $ E.bracket (before sctx) after thing

-- }}}

-- Error handling {{{

data Error
	= UnknownMechanism
	| MechanismCalledTooManyTimes
	| MallocError
	| Base64Error
	| CryptoError
	| SASLPrepError
	| MechanismParseError
	| AuthenticationError
	| IntegrityError
	| NoClientCode
	| NoServerCode
	| NoCallback
	| NoAnonymousToken
	| NoAuthID
	| NoAuthzID
	| NoPassword
	| NoPasscode
	| NoPIN
	| NoService
	| NoHostname
	
	| GSSAPI_ReleaseBufferError
	| GSSAPI_ImportNameError
	| GSSAPI_InitSecContextError
	| GSSAPI_AcceptSecContextError
	| GSSAPI_UnwrapError
	| GSSAPI_WrapError
	| GSSAPI_AquireCredError
	| GSSAPI_DisplayNameError
	| GSSAPI_UnsupportedProtectionError
	| GSSAPI_EncapsulateTokenError
	| GSSAPI_DecapsulateTokenError
	| GSSAPI_InquireMechForSASLNameError
	| GSSAPI_TestOIDSetMemberError
	| GSSAPI_ReleaseOIDSetError
	
	| KerberosV5_InitError
	| KerberosV5_InternalError
	
	| SecurID_ServerNeedAdditionalPasscode
	| SecurID_ServerNeedNewPIN

instance Show Error where
	show = strError

-- | Convert an error code to a human-readable string explanation for the
-- particular error code.
--
-- This string can be used to output a diagnostic message to the user.
strError :: Error -> String
strError err = unsafePerformIO $ gsasl_strerror (cFromError err) >>= F.peekCString

data SASLException = SASLException Error
	deriving (Show, Typeable)

instance E.Exception SASLException

cFromError :: Error -> F.CInt
cFromError e = case e of
	UnknownMechanism -> 2
	MechanismCalledTooManyTimes -> 3
	MallocError -> 7
	Base64Error -> 8
	CryptoError -> 9
	SASLPrepError -> 29
	MechanismParseError -> 30
	AuthenticationError -> 31
	IntegrityError -> 33
	NoClientCode -> 35
	NoServerCode -> 36
	NoCallback -> 51
	NoAnonymousToken -> 52
	NoAuthID -> 53
	NoAuthzID -> 54
	NoPassword -> 55
	NoPasscode -> 56
	NoPIN -> 57
	NoService -> 58
	NoHostname -> 59
	GSSAPI_ReleaseBufferError -> 37
	GSSAPI_ImportNameError -> 38
	GSSAPI_InitSecContextError -> 39
	GSSAPI_AcceptSecContextError -> 40
	GSSAPI_UnwrapError -> 41
	GSSAPI_WrapError -> 42
	GSSAPI_AquireCredError -> 43
	GSSAPI_DisplayNameError -> 44
	GSSAPI_UnsupportedProtectionError -> 45
	GSSAPI_EncapsulateTokenError -> 60
	GSSAPI_DecapsulateTokenError -> 61
	GSSAPI_InquireMechForSASLNameError -> 62
	GSSAPI_TestOIDSetMemberError -> 63
	GSSAPI_ReleaseOIDSetError -> 64
	KerberosV5_InitError -> 46
	KerberosV5_InternalError -> 47
	SecurID_ServerNeedAdditionalPasscode -> 48
	SecurID_ServerNeedNewPIN -> 49

cToError :: F.CInt -> Error
cToError x = case x of
	2 -> UnknownMechanism
	3 -> MechanismCalledTooManyTimes
	7 -> MallocError
	8 -> Base64Error
	9 -> CryptoError
	29 -> SASLPrepError
	30 -> MechanismParseError
	31 -> AuthenticationError
	33 -> IntegrityError
	35 -> NoClientCode
	36 -> NoServerCode
	51 -> NoCallback
	52 -> NoAnonymousToken 
	53 -> NoAuthID
	54 -> NoAuthzID
	55 -> NoPassword
	56 -> NoPasscode
	57 -> NoPIN
	58 -> NoService
	59 -> NoHostname
	37 -> GSSAPI_ReleaseBufferError
	38 -> GSSAPI_ImportNameError
	39 -> GSSAPI_InitSecContextError
	40 -> GSSAPI_AcceptSecContextError
	41 -> GSSAPI_UnwrapError
	42 -> GSSAPI_WrapError
	43 -> GSSAPI_AquireCredError
	44 -> GSSAPI_DisplayNameError
	45 -> GSSAPI_UnsupportedProtectionError
	60 -> GSSAPI_EncapsulateTokenError
	61 -> GSSAPI_DecapsulateTokenError
	62 -> GSSAPI_InquireMechForSASLNameError
	63 -> GSSAPI_TestOIDSetMemberError
	64 -> GSSAPI_ReleaseOIDSetError
	46 -> KerberosV5_InitError
	47 -> KerberosV5_InternalError
	48 -> SecurID_ServerNeedAdditionalPasscode
	49 -> SecurID_ServerNeedNewPIN
	_ -> error $ "Unknown GNU SASL return code: " ++ show x

throw :: Error -> Session a
throw = liftIO . E.throwIO . SASLException

catch :: Session a -> (Error -> Session a) -> Session a
catch m f = do
	sctx <- SessionCtx `fmap` getSessionContext
	Session . liftIO $ E.catch
		(R.runReaderT (unSession m) sctx)
		(\(SASLException err) -> R.runReaderT (unSession (f err)) sctx)

handle :: (Error -> Session a) -> Session a -> Session a
handle = flip catch

try :: Session a -> Session (Either Error a)
try m = catch (fmap Right m) (return . Left)

-- }}}

-- Session Properties {{{

data Property
	= PropertyAuthID
	| PropertyAuthzID
	| PropertyPassword
	| PropertyAnonymousToken
	| PropertyService
	| PropertyHostname
	| PropertyGSSAPIDisplayName
	| PropertyPasscode
	| PropertySuggestedPIN
	| PropertyPIN
	| PropertyRealm
	| PropertyDigestMD5HashedPassword
	| PropertyQOPS
	| PropertyQOP
	| PropertyScramIter
	| PropertyScramSalt
	| PropertyScramSaltedPassword
	
	| ValidateSimple
	| ValidateExternal
	| ValidateAnonymous
	| ValidateGSSAPI
	| ValidateSecurID
	deriving (Show, Eq)

cFromProperty :: Property -> F.CInt
cFromProperty x = case x of
	PropertyAuthID -> 1
	PropertyAuthzID -> 2
	PropertyPassword -> 3
	PropertyAnonymousToken -> 4
	PropertyService -> 5
	PropertyHostname -> 6
	PropertyGSSAPIDisplayName -> 7
	PropertyPasscode -> 8
	PropertySuggestedPIN -> 9
	PropertyPIN -> 10
	PropertyRealm -> 11
	PropertyDigestMD5HashedPassword -> 12
	PropertyQOPS -> 13
	PropertyQOP -> 14
	PropertyScramIter -> 15
	PropertyScramSalt -> 16
	PropertyScramSaltedPassword -> 17
	ValidateSimple -> 500
	ValidateExternal -> 501
	ValidateAnonymous -> 502
	ValidateGSSAPI -> 503
	ValidateSecurID -> 504

cToProperty :: F.CInt -> Property
cToProperty x = case x of
	1 -> PropertyAuthID
	2 -> PropertyAuthzID
	3 -> PropertyPassword
	4 -> PropertyAnonymousToken
	5 -> PropertyService
	6 -> PropertyHostname
	7 -> PropertyGSSAPIDisplayName
	8 -> PropertyPasscode
	9 -> PropertySuggestedPIN
	10 -> PropertyPIN
	11 -> PropertyRealm
	12 -> PropertyDigestMD5HashedPassword
	13 -> PropertyQOPS
	14 -> PropertyQOP
	15 -> PropertyScramIter
	16 -> PropertyScramSalt
	17 -> PropertyScramSaltedPassword
	500 -> ValidateSimple
	501 -> ValidateExternal
	502 -> ValidateAnonymous
	503 -> ValidateGSSAPI
	504 -> ValidateSecurID
	_   -> error $ "Unknown GNU SASL property code: " ++ show x

-- | Store some data in the session for the given property. The data must
-- be @NULL@-terminated.
setProperty :: Property -> B.ByteString -> Session ()
setProperty prop bytes = do
	sctx <- getSessionContext
	liftIO $
		B.useAsCString bytes $
		gsasl_property_set sctx (cFromProperty prop)

-- | Retrieve the data stored in the session for the given property,
-- possibly invoking the current callback to get the value.
getProperty :: Property -> Session (Maybe B.ByteString)
getProperty prop = do
	sctx <- getSessionContext
	liftIO $ do
		cstr <- gsasl_property_get sctx (cFromProperty prop)
		if cstr /= F.nullPtr
			then fmap Just $ B.packCString cstr
			else do
				liftIO $ checkCallbackException sctx
				return Nothing

-- | Retrieve the data stored in the session for the given property,
-- without invoking the current callback.
getPropertyFast :: Property -> Session (Maybe B.ByteString)
getPropertyFast prop = do
	sctx <- getSessionContext
	liftIO $
		gsasl_property_fast sctx (cFromProperty prop) >>=
		F.maybePeek B.packCString

-- }}}

-- Callbacks {{{

type CallbackFn = F.Ptr Context -> F.Ptr SessionCtx -> F.CInt -> IO F.CInt
data CallbackHook = CallbackHook (F.FunPtr CallbackFn) (Property -> Session Progress)

newCallbackHook :: (Property -> Session Progress) -> IO (F.Ptr CallbackHook, F.FunPtr CallbackFn)
newCallbackHook cb = E.bracketOnError
	(wrapCallbackImpl (callbackImpl cb))
	F.freeHaskellFunPtr
	(\funPtr -> let hook = CallbackHook funPtr cb in E.bracketOnError
		(F.newStablePtr hook)
		F.freeStablePtr
		(\stablePtr -> let
			hookPtr = F.castPtr (F.castStablePtrToPtr stablePtr)
			in return (hookPtr, funPtr)))

freeCallbackHook :: F.Ptr CallbackHook -> IO ()
freeCallbackHook ptr = unless (ptr == F.nullPtr) $ do
	let stablePtr = F.castPtrToStablePtr $ F.castPtr ptr
	hook <- F.deRefStablePtr stablePtr
	F.freeStablePtr stablePtr
	let (CallbackHook funPtr _) = hook
	F.freeHaskellFunPtr funPtr

callbackImpl :: (Property -> Session Progress) -> CallbackFn
callbackImpl cb _ sctx cProp = let
	globalIO = error "globalIO is not implemented"
	
	sessionIO = do
		let session = cb $ cToProperty cProp
		fmap cFromProgress $ R.runReaderT (unSession session) (SessionCtx sctx)
	
	onError :: SASLException -> IO F.CInt
	onError (SASLException err) = return $ cFromError err
	
	onException :: E.SomeException -> IO F.CInt
	onException exc = do
		-- A bit ugly; session hooks aren't used anywhere else in
		-- the binding, so the exception is stashed here.
		stablePtr <- F.newStablePtr exc
		gsasl_session_hook_set sctx $ F.castStablePtrToPtr stablePtr
		
		-- standard libgsasl return codes are all >= 0, so using -1
		-- provides an easy way to determine later whether the
		-- exception came from Haskell code.
		return (-1)
	
	catchErrors io = E.catches io [E.Handler onError, E.Handler onException]
	
	in catchErrors $ if sctx == F.nullPtr then globalIO else sessionIO

foreign import ccall "wrapper"
	wrapCallbackImpl :: CallbackFn -> IO (F.FunPtr CallbackFn)

-- Used to check whether a callback threw an exception
checkCallbackException :: F.Ptr SessionCtx -> IO ()
checkCallbackException sctx = do
	hook <- gsasl_session_hook_get sctx
	when (hook /= F.nullPtr) $ do
		let stable = F.castPtrToStablePtr hook
		exc <- F.deRefStablePtr stable
		F.freeStablePtr stable
		E.throwIO (exc :: E.SomeException)

-- | Set the current SASL callback. The callback will be used by mechanisms
-- to discover various parameters, such as usernames and passwords.
setCallback :: (Property -> Session Progress) -> SASL ()
setCallback cb = do
	ctx <- getContext
	liftIO $ do
		freeCallbackHook =<< gsasl_callback_hook_get ctx
		(hook, cbPtr) <- newCallbackHook cb
		gsasl_callback_hook_set ctx hook
		gsasl_callback_set ctx cbPtr

-- | Run the current callback; the property indicates what action the
-- callback is expected to perform.
runCallback :: Property -> Session Progress
runCallback prop = do
	-- This is a bit evil; the first field in Gsasl_session is a Gsasl context,
	-- so it's safe to cast here (assuming they never change the layout).
	ctx <- fmap F.castPtr getSessionContext
	hookPtr <- liftIO $ gsasl_callback_hook_get ctx
	when (hookPtr == F.nullPtr) $ throw NoCallback
	hook <- liftIO $ F.deRefStablePtr $ F.castPtrToStablePtr hookPtr
	let (CallbackHook _ cb) = hook
	cb prop

-- }}}

-- Session IO {{{

data Progress = Complete | NeedsMore
	deriving (Show, Eq)

cFromProgress :: Progress -> F.CInt
cFromProgress x = case x of
	Complete -> 0
	NeedsMore -> 1

-- | Perform one step of SASL authentication. This reads data from the other
-- end, processes it (potentially running the callback), and returns data
-- to be sent back.
--
-- Also returns 'NeedsMore' if authentication is not yet complete.
step :: B.ByteString -> Session (B.ByteString, Progress)
step input = bracketSession get free peek where
	get sctx =
		B.unsafeUseAsCStringLen input $ \(pInput, inputLen) ->
		F.alloca $ \pOutput ->
		F.alloca $ \pOutputLen -> do
		rc <- gsasl_step sctx pInput (fromIntegral inputLen) pOutput pOutputLen
		when (rc /= 0) $ checkCallbackException sctx
		progress <- checkStepRC rc
		cstr <- F.peek pOutput
		cstrLen <- F.peek pOutputLen
		return (cstr, cstrLen, progress)
	
	free (cstr, _, _) = gsasl_free cstr
	peek (cstr, cstrLen, progress) = do
		output <- B.packCStringLen (cstr, fromIntegral cstrLen)
		return (output, progress)

-- | A simple wrapper around 'step' which uses base64 to decode the input
-- and encode the output.
step64 :: B.ByteString -> Session (B.ByteString, Progress)
step64 input = bracketSession get free peek where
	get sctx =
		B.useAsCString input $ \pInput ->
		F.alloca $ \pOutput -> do
		rc <- gsasl_step64 sctx pInput pOutput
		when (rc /= 0) $ checkCallbackException sctx
		progress <- checkStepRC rc
		cstr <- F.peek pOutput
		return (cstr, progress)
	
	free (cstr, _) = gsasl_free cstr
	peek (cstr, progress) = do
		output <- B.packCString cstr
		return (output, progress)

checkStepRC :: F.CInt -> IO Progress
checkStepRC x = case x of
	0 -> return Complete
	1 -> return NeedsMore
	_ -> E.throwIO (SASLException (cToError x))

-- | Encode data according to the negotiated SASL mechanism. This might mean
-- the data is integrity or privacy protected.
encode :: B.ByteString -> Session B.ByteString
encode input = do
	sctx <- getSessionContext
	liftIO $
		B.unsafeUseAsCStringLen input $ \(cstr, cstrLen) ->
		F.alloca $ \pOutput ->
		F.alloca $ \pOutputLen -> do
			rc <- gsasl_encode sctx cstr (fromIntegral cstrLen) pOutput pOutputLen
			when (rc /= 0) $ checkCallbackException sctx
			checkRC rc
			output <- F.peek pOutput
			outputLen <- fromIntegral `fmap` F.peek pOutputLen
			outBytes <- B.packCStringLen (output, outputLen)
			gsasl_free output
			return outBytes

-- | Decode data according to the negotiated SASL mechanism. This might mean
-- the data is integrity or privacy protected.
decode :: B.ByteString -> Session B.ByteString
decode input = do
	sctx <- getSessionContext
	liftIO $
		B.unsafeUseAsCStringLen input $ \(cstr, cstrLen) ->
		F.alloca $ \pOutput ->
		F.alloca $ \pOutputLen -> do
			rc <- gsasl_decode sctx cstr (fromIntegral cstrLen) pOutput pOutputLen
			when (rc /= 0) $ checkCallbackException sctx
			checkRC rc
			output <- F.peek pOutput
			outputLen <- fromIntegral `fmap` F.peek pOutputLen
			outputBytes <- B.packCStringLen (output, outputLen)
			gsasl_free output
			return outputBytes

-- }}}

-- Bundled codecs {{{

toBase64 :: B.ByteString -> B.ByteString
toBase64 input = unsafePerformIO $
	B.unsafeUseAsCStringLen input $ \(pIn, inLen) ->
	F.alloca $ \pOut ->
	F.alloca $ \pOutLen -> do
	gsasl_base64_to pIn (fromIntegral inLen) pOut pOutLen >>= checkRC
	outLen <- F.peek pOutLen
	outPtr <- F.peek pOut
	B.packCStringLen (outPtr, fromIntegral outLen)

fromBase64 :: B.ByteString -> B.ByteString
fromBase64 input = unsafePerformIO $
	B.unsafeUseAsCStringLen input $ \(pIn, inLen) ->
	F.alloca $ \pOut ->
	F.alloca $ \pOutLen -> do
	gsasl_base64_from pIn (fromIntegral inLen) pOut pOutLen >>= checkRC
	outLen <- F.peek pOutLen
	outPtr <- F.peek pOut
	B.packCStringLen (outPtr, fromIntegral outLen)

md5 :: B.ByteString -> B.ByteString
md5 input = unsafePerformIO $
	B.unsafeUseAsCStringLen input $ \(pIn, inLen) ->
	F.alloca $ \pOut ->
	F.allocaBytes 16 $ \outBuf -> do
	F.poke pOut outBuf
	gsasl_md5 pIn (fromIntegral inLen) pOut >>= checkRC
	B.packCStringLen (outBuf, 16)

sha1 :: B.ByteString -> B.ByteString
sha1 input = unsafePerformIO $
	B.unsafeUseAsCStringLen input $ \(pIn, inLen) ->
	F.alloca $ \pOut ->
	F.allocaBytes 20 $ \outBuf -> do
	F.poke pOut outBuf
	gsasl_sha1 pIn (fromIntegral inLen) pOut >>= checkRC
	B.packCStringLen (outBuf, 20)

hmacMD5 :: B.ByteString -- ^ Key
        -> B.ByteString -- ^ Input data
        -> B.ByteString
hmacMD5 key input = unsafePerformIO $
	B.unsafeUseAsCStringLen key $ \(pKey, keyLen) ->
	B.unsafeUseAsCStringLen input $ \(pIn, inLen) ->
	F.alloca $ \pOut ->
	F.allocaBytes 16 $ \outBuf -> do
	F.poke pOut outBuf
	gsasl_hmac_md5 pKey (fromIntegral keyLen) pIn (fromIntegral inLen) pOut >>= checkRC
	B.packCStringLen (outBuf, 16)

hmacSHA1 :: B.ByteString -- ^ Key
         -> B.ByteString -- ^ Input data
         -> B.ByteString
hmacSHA1 key input = unsafePerformIO $
	B.unsafeUseAsCStringLen key $ \(pKey, keyLen) ->
	B.unsafeUseAsCStringLen input $ \(pIn, inLen) ->
	F.alloca $ \pOut ->
	F.allocaBytes 20 $ \outBuf -> do
	F.poke pOut outBuf
	gsasl_hmac_sha1 pKey (fromIntegral keyLen) pIn (fromIntegral inLen) pOut >>= checkRC
	B.packCStringLen (outBuf, 20)

-- | Returns unpredictable data of a given size
nonce :: Integer -> IO B.ByteString
nonce size = F.allocaBytes (fromInteger size) $ \buf -> do
	gsasl_nonce buf (fromIntegral size) >>= checkRC
	B.packCStringLen (buf, fromIntegral size)

-- | Returns cryptographically strong random data of a given size
random :: Integer -> IO B.ByteString
random size = F.allocaBytes (fromInteger size) $ \buf -> do
	gsasl_random buf (fromIntegral size) >>= checkRC
	B.packCStringLen (buf, fromIntegral size)


-- }}}

-- Miscellaneous {{{

checkRC :: F.CInt -> IO ()
checkRC x = case x of
	0 -> return ()
	_ -> E.throwIO (SASLException (cToError x))

unfoldrM :: Monad m => (b -> m (Maybe (a, b))) -> b -> m [a]
unfoldrM m b = m b >>= \x -> case x of
	Just (a, new_b) -> do
		as <- unfoldrM m new_b
		return $ a : as
	Nothing -> return []

-- }}}

-- FFI imports {{{

foreign import ccall "hsgsasl_VERSION_MAJOR"
	hsgsasl_VERSION_MAJOR :: F.CInt

foreign import ccall "hsgsasl_VERSION_MINOR"
	hsgsasl_VERSION_MINOR :: F.CInt

foreign import ccall "hsgsasl_VERSION_PATCH"
	hsgsasl_VERSION_PATCH :: F.CInt

foreign import ccall "hsgsasl_check_version"
	hsgsasl_check_version :: IO F.CInt

foreign import ccall "gsasl.h gsasl_init"
	gsasl_init :: F.Ptr (F.Ptr Context) -> IO F.CInt

foreign import ccall "gsasl.h gsasl_done"
	gsasl_done :: F.Ptr Context -> IO ()

foreign import ccall "gsasl.h gsasl_check_version"
	gsasl_check_version :: F.CString -> IO F.CString

foreign import ccall "gsasl.h gsasl_callback_set"
	gsasl_callback_set :: F.Ptr Context -> F.FunPtr CallbackFn -> IO ()

foreign import ccall "gsasl.h gsasl_callback_hook_get"
	gsasl_callback_hook_get :: F.Ptr Context -> IO (F.Ptr a)

foreign import ccall "gsasl.h gsasl_callback_hook_set"
	gsasl_callback_hook_set :: F.Ptr Context -> F.Ptr a -> IO ()

foreign import ccall "gsasl.h gsasl_session_hook_get"
	gsasl_session_hook_get :: F.Ptr SessionCtx -> IO (F.Ptr a)

foreign import ccall "gsasl.h gsasl_session_hook_set"
	gsasl_session_hook_set :: F.Ptr SessionCtx -> F.Ptr a -> IO ()

foreign import ccall "gsasl.h gsasl_property_set"
	gsasl_property_set :: F.Ptr SessionCtx -> F.CInt -> F.CString -> IO ()

foreign import ccall safe "gsasl.h gsasl_property_get"
	gsasl_property_get :: F.Ptr SessionCtx -> F.CInt -> IO F.CString

foreign import ccall "gsasl.h gsasl_property_fast"
	gsasl_property_fast :: F.Ptr SessionCtx -> F.CInt -> IO F.CString

foreign import ccall "gsasl.h gsasl_client_mechlist"
	gsasl_client_mechlist :: F.Ptr Context -> F.Ptr F.CString -> IO F.CInt

foreign import ccall "gsasl.h gsasl_client_support_p"
	gsasl_client_support_p :: F.Ptr Context -> F.CString -> IO F.CInt

foreign import ccall "gsasl.h gsasl_client_suggest_mechanism"
	gsasl_client_suggest_mechanism :: F.Ptr Context -> F.CString -> IO F.CString

foreign import ccall "gsasl.h gsasl_server_mechlist"
	gsasl_server_mechlist :: F.Ptr Context -> F.Ptr F.CString -> IO F.CInt

foreign import ccall "gsasl.h gsasl_server_support_p"
	gsasl_server_support_p :: F.Ptr Context -> F.CString -> IO F.CInt

foreign import ccall safe "gsasl.h gsasl_client_start"
	gsasl_client_start :: SessionProc

foreign import ccall safe "gsasl.h gsasl_server_start"
	gsasl_server_start :: SessionProc

foreign import ccall safe "gsasl.h gsasl_step"
	gsasl_step :: F.Ptr SessionCtx -> F.CString -> F.CSize -> F.Ptr F.CString -> F.Ptr F.CSize -> IO F.CInt

foreign import ccall safe "gsasl.h gsasl_step64"
	gsasl_step64 :: F.Ptr SessionCtx -> F.CString -> F.Ptr F.CString -> IO F.CInt

foreign import ccall safe "gsasl.h gsasl_finish"
	gsasl_finish :: F.Ptr SessionCtx -> IO ()

foreign import ccall safe "gsasl.h gsasl_encode"
	gsasl_encode :: F.Ptr SessionCtx -> F.CString -> F.CSize -> F.Ptr F.CString -> F.Ptr F.CSize -> IO F.CInt

foreign import ccall safe "gsasl.h gsasl_decode"
	gsasl_decode :: F.Ptr SessionCtx -> F.CString -> F.CSize -> F.Ptr F.CString -> F.Ptr F.CSize -> IO F.CInt

foreign import ccall "gsasl.h gsasl_mechanism_name"
	gsasl_mechanism_name :: F.Ptr SessionCtx -> IO F.CString

foreign import ccall "gsasl.h gsasl_strerror"
	gsasl_strerror :: F.CInt -> IO F.CString

foreign import ccall "gsasl.h gsasl_base64_to"
	gsasl_base64_to :: F.CString -> F.CSize -> F.Ptr F.CString -> F.Ptr F.CSize -> IO F.CInt

foreign import ccall "gsasl.h gsasl_base64_from"
	gsasl_base64_from :: F.CString -> F.CSize -> F.Ptr F.CString -> F.Ptr F.CSize -> IO F.CInt

foreign import ccall "gsasl.h gsasl_md5"
	gsasl_md5 :: F.CString -> F.CSize -> F.Ptr F.CString -> IO F.CInt

foreign import ccall "gsasl.h gsasl_sha1"
	gsasl_sha1 :: F.CString -> F.CSize -> F.Ptr F.CString -> IO F.CInt

foreign import ccall "gsasl.h gsasl_hmac_md5"
	gsasl_hmac_md5 :: F.CString -> F.CSize -> F.CString -> F.CSize -> F.Ptr F.CString -> IO F.CInt

foreign import ccall "gsasl.h gsasl_hmac_sha1"
	gsasl_hmac_sha1 :: F.CString -> F.CSize -> F.CString -> F.CSize -> F.Ptr F.CString -> IO F.CInt

foreign import ccall "gsasl.h gsasl_nonce"
	gsasl_nonce :: F.CString -> F.CSize -> IO F.CInt

foreign import ccall "gsasl.h gsasl_random"
	gsasl_random :: F.CString -> F.CSize -> IO F.CInt

foreign import ccall "gsasl.h gsasl_free"
	gsasl_free :: F.Ptr a -> IO ()

-- }}}
