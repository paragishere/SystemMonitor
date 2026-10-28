package main

import (
	"context"
	"log"
	"sync"
	"time"

	"golang.org/x/sys/windows/svc"
)

const serviceName = "SystemMonitorAgent"

type systemMonitorService struct{}

func (s *systemMonitorService) Execute(
	args []string,
	r <-chan svc.ChangeRequest,
	status chan<- svc.Status,
) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}

	log.Println("[+] System Monitor Service starting...")

	stop := make(chan struct{})
	var wg sync.WaitGroup

	status <- svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()

		ticker := time.NewTicker(CollectionInterval)
		defer ticker.Stop()

		if err := runAgentCycle(); err != nil {
			log.Printf("[!] Initial agent cycle failed: %v", err)
		}

		for {
			select {
			case <-ticker.C:
				if err := runAgentCycle(); err != nil {
					log.Printf("[!] Scheduled agent cycle failed: %v", err)
				}
			case <-stop:
				log.Println("[*] Collection loop stopped.")
				return
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		cfg, err := LoadAgentConfig()
		if err != nil {
			log.Printf("[!] Heartbeat config error: %v", err)
			return
		}

		client, err := NewSecrustClient(cfg)
		if err != nil {
			log.Printf("[!] Heartbeat client error: %v", err)
			return
		}

		ticker := time.NewTicker(cfg.HeartbeatInterval())
		defer ticker.Stop()

		send := func() {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			if err := client.SendHeartbeat(ctx); err != nil {
				log.Printf("[!] Heartbeat failed: %v", err)
				return
			}
			log.Println("[+] Secrust heartbeat accepted")
		}

		send()

		for {
			select {
			case <-ticker.C:
				send()
			case <-stop:
				log.Println("[*] Heartbeat loop stopped.")
				return
			}
		}
	}()

	for {
		change, ok := <-r
		if !ok {
			close(stop)
			wg.Wait()
			return false, 0
		}

		switch change.Cmd {
		case svc.Stop, svc.Shutdown:
			log.Println("[*] Stop request received.")
			status <- svc.Status{State: svc.StopPending}
			close(stop)
			wg.Wait()
			log.Println("[+] System Monitor Service stopped.")
			status <- svc.Status{State: svc.Stopped}
			return false, 0

		case svc.Interrogate:
			status <- change.CurrentStatus
		}
	}
}

func runService() error {
	log.Println("[*] Starting Windows Service:", serviceName)
	return svc.Run(serviceName, &systemMonitorService{})
}
