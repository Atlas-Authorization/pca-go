// Command pca-mpc-party-lwe is the pca-mpc-party command built with the post-quantum endemic base OT: it registers the cgo lweotkit
// implementation with the core, so the ot-sender / ot-receiver roles accept ot.kind "lwe". Everything else is the core command.
// A separate module (like lweotkit itself) so the core module stays cgo-free; link with CGO_LDFLAGS=-L<liblweot dir>.
package main

import (
	"os"

	pca "github.com/Atlas-Authorization/pca-go"
	"github.com/Atlas-Authorization/pca-go/lweotkit"
	"github.com/Atlas-Authorization/pca-go/partycli"
)

// lweImpl adapts lweotkit to the core's byte-level hook.
type lweImpl struct{}

func (lweImpl) Receive(choices []int) ([]byte, [][2][]byte, [][]byte, any, error) {
	m, st, err := lweotkit.Receive(choices, nil)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return m.Rn, m.Points, m.Rhos, st, nil
}

func (lweImpl) SendRandom(rn []byte, points [][2][]byte, rhos [][]byte) ([][2][]byte, [][2][]byte, error) {
	sm, err := lweotkit.SendRandom(&lweotkit.ReceiverMessage{Rn: rn, Points: points, Rhos: rhos}, nil, nil)
	if err != nil {
		return nil, nil, err
	}
	return sm.Ciphertexts, sm.SenderPads, nil
}

func (lweImpl) RecoverRandom(state any, cts [][2][]byte) ([][]byte, error) {
	st, ok := state.(*lweotkit.ReceiverState)
	if !ok {
		return nil, os.ErrInvalid
	}
	return lweotkit.RecoverRandom(st, &lweotkit.SenderMessage{Ciphertexts: cts})
}

// run registers the library and runs the shared command; main only exits with its status.
func run(args []string) int {
	pca.MpcRegisterLweOt(lweImpl{})
	return partycli.Main(args)
}

func main() { os.Exit(run(os.Args)) }
