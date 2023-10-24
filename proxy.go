package safe

import (
	"fmt"
	"log"

	"github.com/freehandle/breeze/socket"
	"github.com/freehandle/breeze/util"
)

func SelfProxyState(conn *socket.SignedConnection, signal chan *Signal) {
	for {
		data, err := conn.Read()
		if err != nil {
			log.Printf("error reading from host: %v", err)
			continue
		}
		if data[0] == 0 {
			if len(data) == 9 {
				signal <- &Signal{
					Signal: 0,
					Data:   data[1:],
				}
			} else {
				log.Print("invalid epoch message")
			}
		} else if data[0] == 1 {
			fmt.Println("tem mensagem aqui")
			if len(data) > 1 {
				signal <- &Signal{
					Signal: 1,
					Data:   data[1:],
				}
			}
		} else if data[0] == 2 {
			fmt.Println("blocoooo")
			blocks := ParseMultiBlocks(data)
			if len(blocks) == 0 {
				log.Printf("invalid multiblocv: %v", err)
			} else {
				log.Printf("multiple blocks: %v", len(blocks))
			}
			for _, block := range blocks {
				epochBytes := make([]byte, 8)
				util.PutUint64(block.epoch, &epochBytes)
				signal <- &Signal{
					Signal: 0,
					Data:   epochBytes,
				}
				for _, action := range block.actions {
					fmt.Println("tem mensagem aqui tb")
					signal <- &Signal{
						Signal: 1,
						Data:   action,
					}
				}
			}
		} else {
			log.Printf("invalid message type: %v", data[0])
		}
	}
}

type blockdata struct {
	epoch   uint64
	actions [][]byte
}

func ParseMultiBlocks(data []byte) []*blockdata {
	if len(data) < 9 {
		return nil
	}
	blocks := make([]*blockdata, 0)
	position := 1
	for {
		block := blockdata{}
		block.epoch, position = util.ParseUint64(data, position)
		block.actions, position = util.ParseActionsArray(data, position)
		if len(block.actions) > 0 {

		}
		blocks = append(blocks, &block)
		if position >= len(data) {
			return blocks
		}
	}
}
