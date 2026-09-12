//go:build cshared

package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);

static int call_host_api(cliproxy_host_api* host, const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	if (host == NULL || host->call == NULL) {
		return 1;
	}
	return host->call(host->host_ctx, method, request, request_len, response);
}

static void free_host_buffer(cliproxy_host_api* host, void* ptr, size_t len) {
	if (host != NULL && host->free_buffer != NULL && ptr != NULL) {
		host->free_buffer(ptr, len);
	}
}
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"sync/atomic"
	"unsafe"

	"cpa-key-policy/internal/plugin"
)

var app = plugin.NewApp()
var hostAPI atomic.Pointer[C.cliproxy_host_api]

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, api *C.cliproxy_plugin_api) C.int {
	if api == nil {
		return 1
	}
	hostAPI.Store(host)
	app.SetHostClient(abiHostClient{})
	api.abi_version = C.uint32_t(plugin.ABIVersion)
	api.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	api.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	api.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeResponse(response, plugin.ErrorEnvelope("invalid_method", "method is required", 400))
		return 1
	}
	var requestBytes []byte
	if request != nil && requestLen > 0 {
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	raw, err := app.HandleMethod(C.GoString(method), requestBytes)
	if err != nil {
		writeResponse(response, plugin.ErrorEnvelope("plugin_error", err.Error(), 500))
		return 1
	}
	writeResponse(response, raw)
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, _ C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {
	app.Shutdown()
	hostAPI.Store(nil)
}

func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}

type abiHostClient struct{}

func (abiHostClient) ListAuths() ([]plugin.HostAuthEntry, error) {
	result, err := callHost(plugin.MethodHostAuthListCallback, map[string]any{})
	if err != nil {
		return nil, err
	}
	var response struct {
		Files []plugin.HostAuthEntry `json:"files"`
	}
	if err := json.Unmarshal(result, &response); err != nil {
		return nil, fmt.Errorf("decode host.auth.list result: %w", err)
	}
	return response.Files, nil
}

func (abiHostClient) GetAuth(authIndex string) (plugin.HostAuthDocument, error) {
	result, err := callHost(plugin.MethodHostAuthGetCallback, map[string]string{"auth_index": authIndex})
	if err != nil {
		return plugin.HostAuthDocument{}, err
	}
	var response plugin.HostAuthDocument
	if err := json.Unmarshal(result, &response); err != nil {
		return plugin.HostAuthDocument{}, fmt.Errorf("decode host.auth.get result: %w", err)
	}
	return response, nil
}

func (abiHostClient) GetAuthRuntime(authIndex string) (plugin.HostAuthEntry, error) {
	result, err := callHost(plugin.MethodHostAuthGetRuntimeCallback, map[string]string{"auth_index": authIndex})
	if err != nil {
		return plugin.HostAuthEntry{}, err
	}
	var response struct {
		Auth plugin.HostAuthEntry `json:"auth"`
	}
	if err := json.Unmarshal(result, &response); err != nil {
		return plugin.HostAuthEntry{}, fmt.Errorf("decode host.auth.get_runtime result: %w", err)
	}
	return response.Auth, nil
}

func (abiHostClient) Do(request plugin.HostHTTPRequest) (plugin.HostHTTPResponse, error) {
	result, err := callHost(plugin.MethodHostHTTPDoCallback, request)
	if err != nil {
		return plugin.HostHTTPResponse{}, err
	}
	var response plugin.HostHTTPResponse
	if err := json.Unmarshal(result, &response); err != nil {
		return plugin.HostHTTPResponse{}, fmt.Errorf("decode host.http.do result: %w", err)
	}
	return response, nil
}

func (abiHostClient) Log(level, message string, fields map[string]any) {
	_, _ = callHost(plugin.MethodHostLogCallback, map[string]any{"level": level, "message": message, "fields": fields})
}

func callHost(method string, payload any) (json.RawMessage, error) {
	host := hostAPI.Load()
	if host == nil {
		return nil, fmt.Errorf("host callback %s unavailable", method)
	}
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal host callback %s: %w", method, err)
	}
	cMethod := C.CString(method)
	defer C.free(unsafe.Pointer(cMethod))
	var response C.cliproxy_buffer
	var requestPtr *C.uint8_t
	if len(rawPayload) > 0 {
		ptr := C.CBytes(rawPayload)
		if ptr == nil {
			return nil, fmt.Errorf("allocate host callback %s", method)
		}
		defer C.free(ptr)
		requestPtr = (*C.uint8_t)(ptr)
	}
	code := C.call_host_api(host, cMethod, requestPtr, C.size_t(len(rawPayload)), &response)
	var rawResponse []byte
	if response.ptr != nil && response.len > 0 {
		rawResponse = C.GoBytes(response.ptr, C.int(response.len))
	}
	if response.ptr != nil {
		C.free_host_buffer(host, response.ptr, response.len)
	}
	if len(rawResponse) == 0 {
		return nil, fmt.Errorf("host callback %s returned no response, code=%d", method, int(code))
	}
	var envelope plugin.Envelope
	if err := json.Unmarshal(rawResponse, &envelope); err != nil {
		return nil, fmt.Errorf("decode host callback envelope %s: %w", method, err)
	}
	if !envelope.OK {
		if envelope.Error != nil {
			return nil, fmt.Errorf("%s: %s", envelope.Error.Code, envelope.Error.Message)
		}
		return nil, fmt.Errorf("host callback %s failed", method)
	}
	if code != 0 {
		return nil, fmt.Errorf("host callback %s returned code=%d", method, int(code))
	}
	return append(json.RawMessage(nil), envelope.Result...), nil
}
