//go:build darwin && cgo

package keystore

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#cgo LDFLAGS: -framework Security
#include <Security/Security.h>
#include <stdlib.h>

static CFStringRef pnx_string(const char *value) {
	return CFStringCreateWithCString(NULL, value, kCFStringEncodingUTF8);
}

static CFMutableDictionaryRef pnx_query(const char *service, const char *account) {
	CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFStringRef serviceValue = pnx_string(service);
	CFStringRef accountValue = pnx_string(account);
	CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(query, kSecAttrService, serviceValue);
	CFDictionarySetValue(query, kSecAttrAccount, accountValue);
	CFDictionarySetValue(query, kSecAttrSynchronizable, kCFBooleanFalse);
	CFDictionarySetValue(query, kSecUseDataProtectionKeychain, kCFBooleanTrue);
	CFDictionarySetValue(query, kSecUseAuthenticationUI, kSecUseAuthenticationUIFail);
	CFRelease(serviceValue);
	CFRelease(accountValue);
	return query;
}

static OSStatus pnx_add(const char *service, const char *account, const void *data, CFIndex length) {
	CFMutableDictionaryRef query = pnx_query(service, account);
	CFDataRef value = CFDataCreate(NULL, data, length);
	CFDictionarySetValue(query, kSecValueData, value);
	CFDictionarySetValue(query, kSecAttrAccessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
	OSStatus status = SecItemAdd(query, NULL);
	CFRelease(value);
	CFRelease(query);
	return status;
}

static OSStatus pnx_update(const char *service, const char *account, const void *data, CFIndex length) {
	CFMutableDictionaryRef query = pnx_query(service, account);
	CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(NULL, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFDataRef value = CFDataCreate(NULL, data, length);
	CFDictionarySetValue(attrs, kSecValueData, value);
	CFDictionarySetValue(attrs, kSecAttrSynchronizable, kCFBooleanFalse);
	CFDictionarySetValue(attrs, kSecAttrAccessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
	OSStatus status = SecItemUpdate(query, attrs);
	CFRelease(value);
	CFRelease(attrs);
	CFRelease(query);
	return status;
}

static OSStatus pnx_get(const char *service, const char *account, CFDataRef *result) {
	CFMutableDictionaryRef query = pnx_query(service, account);
	CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
	CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
	OSStatus status = SecItemCopyMatching(query, (CFTypeRef *)result);
	CFRelease(query);
	return status;
}

static OSStatus pnx_delete(const char *service, const char *account) {
	CFMutableDictionaryRef query = pnx_query(service, account);
	OSStatus status = SecItemDelete(query);
	CFRelease(query);
	return status;
}
*/
import "C"

import (
	"context"
	"errors"
	"unsafe"
)

var (
	errNativeNotFound  = errors.New("native keychain item not found")
	errNativeDuplicate = errors.New("native keychain item already exists")
)

type darwinAccessibility uint8

const darwinAccessibleWhenUnlockedThisDeviceOnly darwinAccessibility = 1

type darwinItem struct {
	Service       string
	Account       string
	Label         string
	Data          []byte
	Accessibility darwinAccessibility
}

type darwinFacade interface {
	Update(context.Context, darwinItem) error
	Add(context.Context, darwinItem) error
	Get(context.Context, darwinItem) ([]byte, error)
	Delete(context.Context, darwinItem) error
}

type darwinBackend struct {
	facade darwinFacade
	gate   chan struct{}
}

func newNativeBackend() (Backend, error) {
	return newDarwinBackend(nativeDarwinFacade{}), nil
}

func newDarwinBackend(facade darwinFacade) *darwinBackend {
	backend := &darwinBackend{facade: facade, gate: make(chan struct{}, 1)}
	backend.gate <- struct{}{}
	return backend
}

func (b *darwinBackend) Put(ctx context.Context, service, account string, secret []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := b.lock(ctx); err != nil {
		return err
	}
	defer b.unlock()
	item := darwinItem{
		Service:       service,
		Account:       account,
		Label:         "PaloNexus Guard credential",
		Data:          secret,
		Accessibility: darwinAccessibleWhenUnlockedThisDeviceOnly,
	}
	err := b.facade.Update(ctx, item)
	if errors.Is(err, errNativeNotFound) {
		err = b.facade.Add(ctx, item)
		if errors.Is(err, errNativeDuplicate) {
			err = b.facade.Update(ctx, item)
		}
	}
	return mapDarwinError(err)
}

func (b *darwinBackend) Get(ctx context.Context, service, account string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := b.lock(ctx); err != nil {
		return nil, err
	}
	defer b.unlock()
	value, err := b.facade.Get(ctx, darwinItem{Service: service, Account: account})
	if err != nil {
		return nil, mapDarwinError(err)
	}
	if value == nil {
		return nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		Zero(value)
		return nil, err
	}
	return value, nil
}

func (b *darwinBackend) Delete(ctx context.Context, service, account string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := b.lock(ctx); err != nil {
		return err
	}
	defer b.unlock()
	err := b.facade.Delete(ctx, darwinItem{Service: service, Account: account})
	if errors.Is(err, errNativeNotFound) {
		return nil
	}
	return mapDarwinError(err)
}

func (b *darwinBackend) lock(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-b.gate:
	}
	if err := ctx.Err(); err != nil {
		b.gate <- struct{}{}
		return err
	}
	return nil
}

func (b *darwinBackend) unlock() { b.gate <- struct{}{} }

func mapDarwinError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, errNativeNotFound):
		return ErrNotFound
	default:
		return ErrUnavailable
	}
}

type nativeDarwinFacade struct{}

func (nativeDarwinFacade) Update(ctx context.Context, item darwinItem) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	service, account := C.CString(item.Service), C.CString(item.Account)
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(account))
	return nativeDarwinStatus(C.pnx_update(service, account, unsafe.Pointer(&item.Data[0]), C.CFIndex(len(item.Data))))
}

func (nativeDarwinFacade) Add(ctx context.Context, item darwinItem) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	service, account := C.CString(item.Service), C.CString(item.Account)
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(account))
	return nativeDarwinStatus(C.pnx_add(service, account, unsafe.Pointer(&item.Data[0]), C.CFIndex(len(item.Data))))
}

func (nativeDarwinFacade) Get(ctx context.Context, item darwinItem) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	service, account := C.CString(item.Service), C.CString(item.Account)
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(account))
	var data C.CFDataRef
	if err := nativeDarwinStatus(C.pnx_get(service, account, &data)); err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(data))
	length := C.CFDataGetLength(data)
	return C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(data)), C.int(length)), nil
}

func (nativeDarwinFacade) Delete(ctx context.Context, item darwinItem) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	service, account := C.CString(item.Service), C.CString(item.Account)
	defer C.free(unsafe.Pointer(service))
	defer C.free(unsafe.Pointer(account))
	return nativeDarwinStatus(C.pnx_delete(service, account))
}

func nativeDarwinStatus(status C.OSStatus) error {
	switch {
	case status == 0:
		return nil
	case status == C.errSecItemNotFound:
		return errNativeNotFound
	case status == C.errSecDuplicateItem:
		return errNativeDuplicate
	default:
		return ErrUnavailable
	}
}
