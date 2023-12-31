package safe

import (
	"log"

	"github.com/freehandle/axe/attorney"
	"github.com/freehandle/breeze/util"
)

type Gateway interface {
	Send(action []byte) error
}

type Signal struct {
	Signal byte
	Data   []byte
}

func IsAxeNonVoid(action []byte) bool {
	if len(action) < 15 {
		return false
	}
	if action[0] != 0 || action[1] != 0 || action[10] != 1 || action[11] != 0 || action[12] != 0 || action[13] != 0 || action[14] == 0 {
		return false
	}
	return true
}

func NewSynergyNode(safe *Safe, signals chan *Signal) {
	for {
		signal := <-signals
		if signal.Signal == 0 {
			safe.epoch, _ = util.ParseUint64(signal.Data, 0)
		} else if signal.Signal == 1 {
			if IsAxeNonVoid(signal.Data) {
				switch attorney.Kind(signal.Data) {
				case attorney.GrantPowerOfAttorneyType:
					grant := attorney.ParseGrantPowerOfAttorney(signal.Data)
					if grant != nil {
						safe.IncorporateGrant(grant)
					}
				case attorney.RevokePowerOfAttorneyType:
					revoke := attorney.ParseRevokePowerOfAttorney(signal.Data)
					if revoke != nil {
						safe.IncorporateRevoke(revoke)
					}
				case attorney.JoinNetworkType:
					join := attorney.ParseJoinNetwork(signal.Data)
					if join != nil {
						safe.IncorporateJoin(join)
					}
				}
			}
		} else {
			log.Printf("invalid signal: %v", signal.Signal)
		}
	}
}
