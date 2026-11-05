package workerport

import (
	"bytes"
	"io"
)

type cappedStatusOutput struct{ bytes.Buffer }

func (b *cappedStatusOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 16384 {
		return 0, io.ErrShortBuffer
	}
	return b.Buffer.Write(p)
}
