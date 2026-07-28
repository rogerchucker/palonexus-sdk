package keystore

// NativeBackend selects only the native user secret store on supported
// platforms. It never selects an encrypted or plaintext file fallback.
func NativeBackend() (Backend, error) {
	return newNativeBackend()
}
