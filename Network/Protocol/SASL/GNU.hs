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

{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.Protocol.SASL.GNU
	(
	-- * Library Information
	  libraryVersion
	, headerVersion
	
	-- * SASL Contexts
	, SASL
	, runSASL
	--, setCallback
	--, runCallback
	
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

import qualified Control.Exception as E
import qualified Data.ByteString as B
import qualified Data.ByteString.Unsafe as B
import Data.ByteString.Char8 ()
import Data.Char (isDigit)
import qualified Foreign as F
import qualified Foreign.C as F
import System.IO.Unsafe (unsafePerformIO)
import Control.Monad.IO.Class (MonadIO, liftIO)
import qualified Control.Monad.Trans.Reader as R
import qualified Text.ParserCombinators.ReadP as P

-- }}}

-- Library Information {{{

headerVersion :: (Integer, Integer, Integer)
headerVersion = (major, minor, patch) where
	major = toInteger hsgsasl_VERSION_MAJOR
	minor = toInteger hsgsasl_VERSION_MINOR
	patch = toInteger hsgsasl_VERSION_PATCH

libraryVersion :: (Integer, Integer, Integer)
libraryVersion = unsafePerformIO io where
	parseVersion str = case P.readP_to_S parser str of
		[] -> Nothing
		((parsed, _):_) -> Just parsed
	parser = do
		majorS <- P.munch1 isDigit
		P.char '.'
		minorS <- P.munch1 isDigit
		P.char '.'
		patchS <- P.munch1 isDigit
		P.eof
		return (read majorS, read minorS, read patchS)
	io = do
		cstr <- gsasl_check_version F.nullPtr
		maybeStr <- F.maybePeek F.peekCString cstr
		return $ case maybeStr >>= parseVersion of
			Just version -> version
			Nothing -> error $ "Invalid version string: " ++ show maybeStr

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
	freeContext (Context ptr) = gsasl_done ptr

getContext :: SASL (F.Ptr Context)
getContext = SASL $ do
	Context ptr <- R.ask
	return ptr

setCallback :: (Property -> Session ()) -> SASL ()
setCallback = undefined

runCallback :: Property -> Session ()
runCallback = undefined

-- }}}

-- Mechanisms {{{

newtype Mechanism = Mechanism B.ByteString
	deriving (Show, Eq)

clientMechanisms :: SASL [Mechanism]
clientMechanisms = do
	ctx <- getContext
	liftIO $ F.alloca $ \pStr -> do
		gsasl_client_mechlist ctx pStr >>= checkRC
		cstr <- F.peek pStr
		mechanisms <- splitMechListPtr cstr
		gsasl_free cstr
		return mechanisms

clientSupports :: Mechanism -> SASL Bool
clientSupports (Mechanism name) = do
	ctx <- getContext
	liftIO $ B.useAsCString name $ \pName -> do
		cres <- gsasl_client_support_p ctx pName
		return $ cres == 1

clientSuggestMechanism :: [Mechanism] -> SASL (Maybe Mechanism)
clientSuggestMechanism mechs = do
	let bytes = B.intercalate " " [x | Mechanism x <- mechs]
	ctx <- getContext
	liftIO $ B.useAsCString bytes $ \pMechlist ->
		gsasl_client_suggest_mechanism ctx pMechlist >>=
		F.maybePeek (fmap Mechanism . B.packCString)

serverMechanisms :: SASL [Mechanism]
serverMechanisms = do
	ctx <- getContext
	liftIO $ F.alloca $ \pStr -> do
		gsasl_server_mechlist ctx pStr >>= checkRC
		cstr <- F.peek pStr
		mechanisms <- splitMechListPtr cstr
		gsasl_free cstr
		return mechanisms

serverSupports :: Mechanism -> SASL Bool
serverSupports (Mechanism name) = do
	ctx <- getContext
	liftIO $ B.useAsCString name $ \pName -> do
		cres <- gsasl_server_support_p ctx pName
		return $ cres == 1

splitMechListPtr :: F.CString -> IO [Mechanism]
splitMechListPtr ptr = unfoldrM step (ptr, ptr, 0, True) where
	step (_, _, _, False) = return Nothing
	step (p0, pi, i, _) = F.peek pi >>= \chr -> let
		pi' = F.plusPtr pi 1
		peek continue = if i == 0
			then step (pi', pi', 0, continue)
			else do
				bytes <- B.packCStringLen (p0, i)
				return $ Just (Mechanism bytes, (pi', pi', 0, continue))
		in case chr of
			0x00 -> peek False
			0x20 -> peek True
			_    -> step (p0, pi', i + 1, True)

-- }}}

-- SASL Sessions {{{

newtype SessionCtx = SessionCtx (F.Ptr SessionCtx)
newtype Session a = Session { unSession :: R.ReaderT SessionCtx SASL a }

instance Functor Session where
	fmap f = Session . fmap f . unSession

instance Monad Session where
	return = Session . return
	(>>=) m f = Session $ unSession m >>= unSession . f

instance MonadIO Session where
	liftIO = Session . liftIO

type SessionProc = F.Ptr Context -> F.CString -> F.Ptr (F.Ptr SessionCtx) -> IO F.CInt

runSession :: SessionProc -> Mechanism -> Session a -> SASL a
runSession start (Mechanism mech) session = sasl where
	sasl = do
		ctx <- getContext
		liftIO $ (withSession ctx) (io ctx)
	freeSession (SessionCtx ptr) = gsasl_finish ptr
	newSession ctx =
		B.unsafeUseAsCString mech $ \pMech ->
		F.alloca $ \pSessionCtx -> do
			start ctx pMech pSessionCtx >>= checkRC
			SessionCtx `fmap` F.peek pSessionCtx
	withSession ctx = E.bracket (newSession ctx) freeSession
	io ctx sessionCtx =
		R.runReaderT (unSASL (
		R.runReaderT (unSession session) sessionCtx)) (Context ctx)

runClient :: Mechanism -> Session a -> SASL a
runClient = runSession gsasl_client_start

runServer :: Mechanism -> Session a -> SASL a
runServer = runSession gsasl_server_start

getSessionContext :: Session (F.Ptr SessionCtx)
getSessionContext = Session $ do
	SessionCtx sctx <- R.ask
	return sctx

mechanismName :: Session Mechanism
mechanismName = do
	sctx <- getSessionContext
	liftIO $ do
		cstr <- gsasl_mechanism_name sctx
		Mechanism `fmap` B.packCString cstr

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

setProperty :: Property -> B.ByteString -> Session ()
setProperty prop bytes = do
	sctx <- getSessionContext
	liftIO $
		B.useAsCString bytes $
		gsasl_property_set sctx (cFromProperty prop)

getProperty :: Property -> Session (Maybe B.ByteString)
getProperty prop = do
	sctx <- getSessionContext
	liftIO $
		gsasl_property_get sctx (cFromProperty prop) >>=
		F.maybePeek B.packCString

getPropertyFast :: Property -> Session (Maybe B.ByteString)
getPropertyFast prop = do
	sctx <- getSessionContext
	liftIO $
		gsasl_property_fast sctx (cFromProperty prop) >>=
		F.maybePeek B.packCString

-- }}}

-- Session IO {{{

data Progress = Complete | NeedsMore
	deriving (Show, Eq)

step :: B.ByteString -> Session (B.ByteString, Progress)
step input = do
	sctx <- getSessionContext
	liftIO $
		B.unsafeUseAsCStringLen input $ \(pInput, inputLen) ->
		F.alloca $ \pOutput ->
		F.alloca $ \pOutputLen -> do
		rc <- gsasl_step sctx pInput (fromIntegral inputLen) pOutput pOutputLen
		progress <- case rc of
			0 -> return Complete
			1 -> return NeedsMore
			_ -> throwError rc
		cstr <- F.peek pOutput
		cstrLen <- F.peek pOutputLen
		output <- B.packCStringLen (cstr, fromIntegral cstrLen)
		gsasl_free cstr
		return (output, progress)

step64 :: B.ByteString -> Session (B.ByteString, Progress)
step64 input = do
	sctx <- getSessionContext
	liftIO $
		B.useAsCString input $ \pInput ->
		F.alloca $ \pOutput -> do
		rc <- gsasl_step64 sctx pInput pOutput
		progress <- case rc of
			0 -> return Complete
			1 -> return NeedsMore
			_ -> throwError rc
		cstr <- F.peek pOutput 
		output <- B.packCString cstr
		gsasl_free cstr
		return (output, progress)

encode :: B.ByteString -> Session B.ByteString
encode input = do
	sctx <- getSessionContext
	liftIO $
		B.unsafeUseAsCStringLen input $ \(cstr, cstrLen) ->
		F.alloca $ \pOutput ->
		F.alloca $ \pOutputLen -> do
			gsasl_encode sctx cstr (fromIntegral cstrLen) pOutput pOutputLen >>= checkRC
			output <- F.peek pOutput
			outputLen <- fromIntegral `fmap` F.peek pOutputLen
			outBytes <- B.packCStringLen (output, outputLen)
			gsasl_free output
			return outBytes

decode :: B.ByteString -> Session B.ByteString
decode input = do
	sctx <- getSessionContext
	liftIO $
		B.unsafeUseAsCStringLen input $ \(cstr, cstrLen) ->
		F.alloca $ \pOutput ->
		F.alloca $ \pOutputLen -> do
			gsasl_decode sctx cstr (fromIntegral cstrLen) pOutput pOutputLen >>= checkRC
			output <- F.peek pOutput
			outputLen <- fromIntegral `fmap` F.peek pOutputLen
			outputBytes <- B.packCStringLen (output, outputLen)
			gsasl_free output
			return outputBytes

-- }}}

-- TODO: gsasl_strerror?

-- TODO: gsasl_strerror_name?

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

hmacMD5 :: B.ByteString -> B.ByteString -> B.ByteString
hmacMD5 key input = unsafePerformIO $
	B.unsafeUseAsCStringLen key $ \(pKey, keyLen) ->
	B.unsafeUseAsCStringLen input $ \(pIn, inLen) ->
	F.alloca $ \pOut ->
	F.allocaBytes 16 $ \outBuf -> do
	F.poke pOut outBuf
	gsasl_hmac_md5 pKey (fromIntegral keyLen) pIn (fromIntegral inLen) pOut >>= checkRC
	B.packCStringLen (outBuf, 16)

hmacSHA1 :: B.ByteString -> B.ByteString -> B.ByteString
hmacSHA1 key input = unsafePerformIO $
	B.unsafeUseAsCStringLen key $ \(pKey, keyLen) ->
	B.unsafeUseAsCStringLen input $ \(pIn, inLen) ->
	F.alloca $ \pOut ->
	F.allocaBytes 20 $ \outBuf -> do
	F.poke pOut outBuf
	gsasl_hmac_sha1 pKey (fromIntegral keyLen) pIn (fromIntegral inLen) pOut >>= checkRC
	B.packCStringLen (outBuf, 20)

nonce :: Integer -> IO B.ByteString
nonce size = F.allocaBytes (fromInteger size) $ \buf -> do
	gsasl_nonce buf (fromIntegral size) >>= checkRC
	B.packCStringLen (buf, fromIntegral size)

random :: Integer -> IO B.ByteString
random size = F.allocaBytes (fromInteger size) $ \buf -> do
	gsasl_random buf (fromIntegral size) >>= checkRC
	B.packCStringLen (buf, fromIntegral size)


-- }}}

-- Miscellaneous {{{

checkRC :: F.CInt -> IO ()
checkRC 0 = return ()
checkRC x = throwError x

throwError :: F.CInt -> IO a
throwError x = E.throwIO $ E.ErrorCall $ "Error code " ++ show x

unfoldrM :: Monad m => (b -> m (Maybe (a, b))) -> b -> m [a]
unfoldrM m b = m b >>= \x -> case x of
	Just (a, new_b) -> do
		as <- unfoldrM m new_b
		return $ a : as
	Nothing -> return []

-- }}}

-- FFI imports {{{

foreign import ccall unsafe "hsgsasl_VERSION_MAJOR"
	hsgsasl_VERSION_MAJOR :: F.CInt

foreign import ccall unsafe "hsgsasl_VERSION_MINOR"
	hsgsasl_VERSION_MINOR :: F.CInt

foreign import ccall unsafe "hsgsasl_VERSION_PATCH"
	hsgsasl_VERSION_PATCH :: F.CInt

foreign import ccall unsafe "gsasl.h gsasl_init"
	gsasl_init :: F.Ptr (F.Ptr Context) -> IO F.CInt

foreign import ccall unsafe "gsasl.h gsasl_done"
	gsasl_done :: F.Ptr Context -> IO ()

foreign import ccall unsafe "gsasl.h gsasl_check_version"
	gsasl_check_version :: F.CString -> IO F.CString

foreign import ccall unsafe "gsasl.h gsasl_callback_hook_get"
	gsasl_callback_hook_get :: F.Ptr Context -> IO (F.Ptr ())

foreign import ccall unsafe "gsasl.h gsasl_callback_hook_set"
	gsasl_callback_hook_set :: F.Ptr Context -> F.Ptr () -> IO ()

foreign import ccall unsafe "gsasl.h gsasl_property_set"
	gsasl_property_set :: F.Ptr SessionCtx -> F.CInt -> F.CString -> IO ()

foreign import ccall safe "gsasl.h gsasl_property_get"
	gsasl_property_get :: F.Ptr SessionCtx -> F.CInt -> IO F.CString

foreign import ccall safe "gsasl.h gsasl_property_fast"
	gsasl_property_fast :: F.Ptr SessionCtx -> F.CInt -> IO F.CString

foreign import ccall unsafe "gsasl.h gsasl_client_mechlist"
	gsasl_client_mechlist :: F.Ptr Context -> F.Ptr F.CString -> IO F.CInt

foreign import ccall unsafe "gsasl.h gsasl_client_support_p"
	gsasl_client_support_p :: F.Ptr Context -> F.CString -> IO F.CInt

foreign import ccall unsafe "gsasl.h gsasl_client_suggest_mechanism"
	gsasl_client_suggest_mechanism :: F.Ptr Context -> F.CString -> IO F.CString

foreign import ccall unsafe "gsasl.h gsasl_server_mechlist"
	gsasl_server_mechlist :: F.Ptr Context -> F.Ptr F.CString -> IO F.CInt

foreign import ccall unsafe "gsasl.h gsasl_server_support_p"
	gsasl_server_support_p :: F.Ptr Context -> F.CString -> IO F.CInt

foreign import ccall safe "gsasl.h gsasl_client_start"
	gsasl_client_start :: SessionProc

foreign import ccall safe "gsasl.h gsasl_server_start"
	gsasl_server_start :: SessionProc

foreign import ccall safe "gsasl.h gsasl_step"
	gsasl_step :: F.Ptr SessionCtx -> F.CString -> F.CSize -> F.Ptr F.CString -> F.Ptr F.CSize -> IO F.CInt

foreign import ccall safe "gsasl.h gsasl_step64"
	gsasl_step64 :: F.Ptr SessionCtx -> F.CString -> F.Ptr F.CString -> IO F.CInt

foreign import ccall unsafe "gsasl.h gsasl_finish"
	gsasl_finish :: F.Ptr SessionCtx -> IO ()

foreign import ccall unsafe "gsasl.h gsasl_encode"
	gsasl_encode :: F.Ptr SessionCtx -> F.CString -> F.CSize -> F.Ptr F.CString -> F.Ptr F.CSize -> IO F.CInt

foreign import ccall unsafe "gsasl.h gsasl_decode"
	gsasl_decode :: F.Ptr SessionCtx -> F.CString -> F.CSize -> F.Ptr F.CString -> F.Ptr F.CSize -> IO F.CInt

foreign import ccall unsafe "gsasl.h gsasl_mechanism_name"
	gsasl_mechanism_name :: F.Ptr SessionCtx -> IO F.CString

foreign import ccall unsafe "gsasl.h gsasl_base64_to"
	gsasl_base64_to :: F.CString -> F.CSize -> F.Ptr F.CString -> F.Ptr F.CSize -> IO F.CInt

foreign import ccall unsafe "gsasl.h gsasl_base64_from"
	gsasl_base64_from :: F.CString -> F.CSize -> F.Ptr F.CString -> F.Ptr F.CSize -> IO F.CInt

foreign import ccall unsafe "gsasl.h gsasl_md5"
	gsasl_md5 :: F.CString -> F.CSize -> F.Ptr F.CString -> IO F.CInt

foreign import ccall unsafe "gsasl.h gsasl_sha1"
	gsasl_sha1 :: F.CString -> F.CSize -> F.Ptr F.CString -> IO F.CInt

foreign import ccall unsafe "gsasl.h gsasl_hmac_md5"
	gsasl_hmac_md5 :: F.CString -> F.CSize -> F.CString -> F.CSize -> F.Ptr F.CString -> IO F.CInt

foreign import ccall unsafe "gsasl.h gsasl_hmac_sha1"
	gsasl_hmac_sha1 :: F.CString -> F.CSize -> F.CString -> F.CSize -> F.Ptr F.CString -> IO F.CInt

foreign import ccall unsafe "gsasl.h gsasl_nonce"
	gsasl_nonce :: F.CString -> F.CSize -> IO F.CInt

foreign import ccall unsafe "gsasl.h gsasl_random"
	gsasl_random :: F.CString -> F.CSize -> IO F.CInt

foreign import ccall unsafe "gsasl.h gsasl_free"
	gsasl_free :: F.Ptr a -> IO ()

-- }}}
