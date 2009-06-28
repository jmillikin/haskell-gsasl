{- Copyright (C) 2009 John Millikin <jmillikin@gmail.com>
   
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
-}

{-# LANGUAGE ForeignFunctionInterface #-}

#include <gsasl.h>

module Network.Protocol.SASL.GSASL (
	 ReturnCode(..)
	,Property(..)
	,Context
	,Session
	,Mechanism
	,CallbackComputation
	
	,mkContext
	,clientMechanisms
	,serverMechanisms
	,clientSupportP
	,serverSupportP
	,clientSuggestMechanism
	,register
	,callbackSet
	,callback
	,propertySet
	,propertyFast
	,propertyGet
	,clientStart
	,serverStart
	,step
	,step64
	,encode
	,decode
	) where

import Foreign
import Foreign.C
import Data.List (intercalate)
import Control.Exception (bracket)

{#enum Gsasl_rc as ReturnCode {} deriving (Show) #}
{#enum Gsasl_property as Property {} deriving (Show) #}
{#enum Gsasl_saslprep_flags as SaslPrepFlags {} deriving (Show) #}

{#pointer *Gsasl as ContextPtr -> Context #}
{#pointer *Gsasl_session as SessionPtr -> Session #}
{#pointer *Gsasl_mechanism as MechanismPtr -> Mechanism #}

data Context = Context { rawContext :: ContextPtr }
data Session = Session { rawSession :: SessionPtr }
data Mechanism = Mechanism { rawMechanism :: MechanismPtr }

type CallbackComputation = (Context -> Session -> Property -> IO ReturnCode)
type CallbackComputationPtr = (ContextPtr -> SessionPtr -> CInt -> IO CInt)

-------------------------------------------------------------------------------

cToEnum :: (Enum a) => CInt -> a
cToEnum = toEnum . fromIntegral

cFromEnum :: (Enum a) => a -> CInt
cFromEnum = fromIntegral . fromEnum

cSpacedStringFromList :: [String] -> (CString -> IO a) -> IO a
cSpacedStringFromList xs f = let spaced = intercalate " " xs in
	withCString spaced f

cToMaybeString :: CString -> IO (Maybe String)
cToMaybeString s
	| s == nullPtr = return Nothing
	| otherwise    = peekCString s >>= return . Just

cFromMaybe :: (a -> Ptr b) -> Maybe a -> Ptr b
cFromMaybe _ Nothing  = nullPtr
cFromMaybe f (Just x) = f x

cFromMaybeContext = cFromMaybe rawContext

-------------------------------------------------------------------------------

checkRC :: CInt -> IO ()
checkRC x = let rc = cToEnum x in do
	putStrLn $ "rc = " ++ (show rc)
	message <- gsasl_strerror rc
	case rc of
		GSASL_OK -> return ()
		_ -> error message

checkStepRC :: CInt -> IO ReturnCode
checkStepRC x = let rc = cToEnum x in do
	putStrLn $ "rc = " ++ (show rc)
	message <- gsasl_strerror rc
	case rc of
		GSASL_OK -> return rc
		GSASL_NEEDS_MORE -> return rc
		_ -> error message

-- Context procedures
mkContext :: IO Context
mkContext =
	alloca $ \pctxt -> do
	gsasl_init pctxt
	rawCtxt <- peek pctxt
	let ctxt = Context rawCtxt
	ctxtPtr <- newStablePtr ctxt
	callbackHookSet rawCtxt (castStablePtrToPtr ctxtPtr)
	return ctxt

{#fun gsasl_init {
	id `Ptr ContextPtr'
	} -> `()' checkRC* #}

{- -- TODO: make this automatic in mkContext
{#fun gsasl_done {
	rawContext `Context'
	} -> `()' #}
-}

clientMechanisms :: Context -> IO [String]
clientMechanisms ctxt =
	alloca $ \pstrs -> do
	gsasl_client_mechlist ctxt pstrs >>= checkRC
	cstrs <- peek pstrs
	strs <- peekCString cstrs
	free cstrs
	return $ split ' ' strs

{#fun gsasl_client_mechlist {
	 rawContext `Context'
	,id `Ptr CString'
	} -> `CInt' id #}

serverMechanisms :: Context -> IO [String]
serverMechanisms ctxt =
	alloca $ \pstrs -> do
	gsasl_server_mechlist ctxt pstrs >>= checkRC
	cstrs <- peek pstrs
	strs <- peekCString cstrs
	free cstrs
	return $ split ' ' strs

{#fun gsasl_server_mechlist {
	 rawContext `Context'
	,id `Ptr CString'
	} -> `CInt' id #}

{#fun gsasl_client_support_p as clientSupportP {
	 rawContext `Context'
	,`String'
	} -> `Bool' toBool #}

{#fun gsasl_server_support_p as serverSupportP {
	 rawContext `Context'
	,`String'
	} -> `Bool' toBool #}

{#fun gsasl_client_suggest_mechanism as clientSuggestMechanism {
	 rawContext `Context'
	,cSpacedStringFromList* `[String]'
	} -> `Maybe String' cToMaybeString* #}

{#fun gsasl_register as register {
	 rawContext `Context'
	,rawMechanism `Mechanism'
	} -> `()' checkRC* #}

-- Callback management
{#fun gsasl_callback_set as callbackSet {
	 rawContext `Context'
	,mkCallbackWrapper* `CallbackComputation'
	} -> `()' #}

mkCallbackWrapper :: CallbackComputation -> (FunPtr CallbackComputationPtr -> IO a) -> IO a
mkCallbackWrapper comp block = bracket
	(callbackWrapper $ mkCallbackWrapper' comp)
	--(freeHaskellFunPtr)
	(\_ -> return ())
	(block)

mkCallbackWrapper' :: CallbackComputation -> CallbackComputationPtr
mkCallbackWrapper' comp pCtxt pSession cProp = do
	callbackHook <- callbackHookGet pCtxt
	let ctxtStablePtr = castPtrToStablePtr callbackHook
	ctxt <- (deRefStablePtr ctxtStablePtr :: IO Context)
	
	sessionHook <- sessionHookGet pSession
	let sessStablePtr = castPtrToStablePtr sessionHook
	session <- (deRefStablePtr sessStablePtr :: IO Session)
	
	let prop = (cToEnum cProp :: Property)
	return . cFromEnum =<< comp ctxt session prop

foreign import ccall "wrapper"
	callbackWrapper :: CallbackComputationPtr -> IO (FunPtr CallbackComputationPtr)

{#fun gsasl_callback  as callback {
	 cFromMaybeContext `Maybe Context'
	,rawSession `Session'
	,cFromEnum `Property'
	} -> `()' checkRC* #}

{#fun gsasl_callback_hook_set as callbackHookSet {
	 id `ContextPtr'
	,id `Ptr ()'
	} -> `()' #}

{#fun gsasl_callback_hook_get as callbackHookGet {
	 id `ContextPtr'
	} -> `Ptr ()' id #}

{#fun gsasl_session_hook_set as sessionHookSet {
	 id `SessionPtr'
	,id `Ptr ()'
	} -> `()' #}

{#fun gsasl_session_hook_get as sessionHookGet {
	 id `SessionPtr'
	} -> `Ptr ()' id #}

-- Property set/get
{#fun gsasl_property_set as propertySet {
	 rawSession `Session'
	,cFromEnum `Property'
	, `String'
	} -> `()' #}

{#fun gsasl_property_fast as propertyFast {
	 rawSession `Session'
	,cFromEnum `Property'
	} -> `Maybe String' cToMaybeString* #}

{#fun gsasl_property_get as propertyGet {
	 rawSession `Session'
	,cFromEnum `Property'
	} -> `Maybe String' cToMaybeString* #}

-- Session procedures
clientStart :: Context -> String -> IO Session
clientStart ctxt s =
	alloca $ \psess -> do
	gsasl_client_start ctxt s psess
	rawSession <- peek psess
	let session = Session rawSession
	sessionPtr <- newStablePtr session
	sessionHookSet rawSession (castStablePtrToPtr sessionPtr)
	return session

{#fun gsasl_client_start {
	 rawContext `Context'
	,`String'
	,id `Ptr SessionPtr'
	} -> `()' checkRC* #}

serverStart :: Context -> String -> IO Session
serverStart ctxt s =
	alloca $ \psess -> do
	gsasl_server_start ctxt s psess
	rawSession <- peek psess
	let session = Session rawSession
	sessionPtr <- newStablePtr session
	sessionHookSet rawSession (castStablePtrToPtr sessionPtr)
	return session

{#fun gsasl_server_start {
	 rawContext `Context'
	,`String'
	,id `Ptr SessionPtr'
	} -> `()' checkRC* #}

step :: Session -> String -> IO (String, ReturnCode)
step s input =
	withCStringLen input $ \(cInput, cInputLen) -> do
	alloca $ \pOutChars -> do
	alloca $ \pOutLen -> do
	rc <- checkStepRC =<< gsasl_step (rawSession s) cInput (fromIntegral cInputLen) pOutChars pOutLen
	outChars <- peek pOutChars
	outLen <- peek pOutLen
	output <- peekCStringLen (outChars, fromIntegral outLen)
	free outChars
	return (output, rc)

gsasl_step :: SessionPtr -> CString -> CUInt -> Ptr CString -> Ptr CUInt -> IO CInt
gsasl_step = {#call gsasl_step as gsasl_step' #}

step64 :: Session -> String -> IO (String, ReturnCode)
step64 s input =
	withCString input $ \cInput -> do
	alloca $ \pOutChars -> do
	rc <- checkStepRC =<< gsasl_step64 (rawSession s) cInput pOutChars
	outChars <- peek pOutChars
	output <- peekCString outChars
	free outChars
	return (output, rc)

gsasl_step64 :: SessionPtr -> CString -> Ptr CString -> IO CInt
gsasl_step64 = {#call gsasl_step64 as gsasl_step64' #}

{- -- TODO: make this automatic in client/serverStart
{#fun gsasl_finish as finish {
	 rawSession `Session'
	} -> `()' #}
-}

encode :: Session -> String -> IO String
encode = encodeDecodeImpl {#call gsasl_encode #}

decode :: Session -> String -> IO String
decode = encodeDecodeImpl {#call gsasl_decode #}

encodeDecodeImpl cfunc s input =
	withCStringLen input $ \(cInput, cInputLen) -> do
	alloca $ \pOutChars -> do
	alloca $ \pOutLen -> do
	checkRC =<< cfunc (rawSession s) cInput (fromIntegral cInputLen) pOutChars pOutLen
	outChars <- peek pOutChars
	outLen <- peek pOutLen
	output <- peekCStringLen (outChars, fromIntegral outLen)
	free pOutChars
	return output

-- Error information
{#fun gsasl_strerror {
	 cFromEnum `ReturnCode'
	} -> `String' #}

-------------------------------------------------------------------------------

split :: (Eq a) => a -> [a] -> [[a]]
split x ys = filter (not . null) $ split' [] [] x ys

split' :: (Eq a) => [a] -> [[a]] -> a -> [a] -> [[a]]
split' prev acc _     [] = acc ++ [prev]
split' prev acc x (y:ys)
 | x == y = split' [] (acc ++ [prev]) x ys
 | otherwise = split' (prev ++ [y]) acc x ys
