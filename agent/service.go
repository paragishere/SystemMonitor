package main

import (
	"log"
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

	// Tell Windows Service Control Manager that the service is starting.
	status <- svc.Status{
		State:   svc.StartPending,
		Accepts: 0,
	}

	log.Println("[+] System Monitor Service starting...")

	// Service is now running.
	status <- svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	}

	// Run the existing agent in a separate goroutine.
	stop := make(chan struct{})

	go func() {
		ticker := time.NewTicker(CollectionInterval)
		defer ticker.Stop()

		// Run immediately when service starts.
		log.Println("[*] Running initial agent cycle...")
		runAgentCycle()

		for {
			select {
			case <-ticker.C:
				log.Println("[*] Running scheduled agent cycle...")
				runAgentCycle()

			case <-stop:
				log.Println("[*] Agent collection stopped.")
				return
			}
		}
	}()

	// Wait for Windows service control commands.
	for {
		change := <-r

		switch change.Cmd {

		case svc.Stop, svc.Shutdown:
			log.Println("[*] Stop request received.")

			status <- svc.Status{
				State:   svc.StopPending,
				Accepts: 0,
			}

			close(stop)

			time.Sleep(1 * time.Second)

			log.Println("[+] System Monitor Service stopped.")

			status <- svc.Status{
				State: svc.Stopped,
			}

			return false, 0

		case svc.Interrogate:
			status <- change.CurrentStatus
		}
	}
}

func runService() error {
	log.Println("[*] Starting Windows Service:", serviceName)

	return svc.Run(
		serviceName,
		&systemMonitorService{},
	)
}
