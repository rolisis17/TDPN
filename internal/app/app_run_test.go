package app

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestAppRunCancelsSiblingOnFirstRealErrorAndWaits(t *testing.T) {
	boom := errors.New("boom")
	siblingStarted := make(chan struct{})
	siblingStopped := make(chan struct{})

	err := runRunners(context.Background(), []func(context.Context) error{
		func(context.Context) error {
			<-siblingStarted
			return boom
		},
		func(ctx context.Context) error {
			close(siblingStarted)
			<-ctx.Done()
			close(siblingStopped)
			return ctx.Err()
		},
	})

	if !errors.Is(err, boom) {
		t.Fatalf("runRunners error=%v want boom", err)
	}
	if err == nil || !strings.Contains(err.Error(), "node stopped") {
		t.Fatalf("runRunners error=%v want node stopped wrapper", err)
	}
	select {
	case <-siblingStopped:
	default:
		t.Fatalf("expected runRunners to wait for canceled sibling")
	}
}

func TestAppRunParentCancellationIsNormalStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	runnerStarted := make(chan struct{})

	errCh := make(chan error, 1)
	go func() {
		errCh <- runRunners(ctx, []func(context.Context) error{
			func(ctx context.Context) error {
				close(runnerStarted)
				<-ctx.Done()
				return ctx.Err()
			},
		})
	}()

	<-runnerStarted
	cancel()

	if err := <-errCh; err != nil {
		t.Fatalf("runRunners error=%v want nil", err)
	}
}
