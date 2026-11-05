package toolbroker

import (
	"context"
	"time"
)

// This fixed helper requests the final credential only from the inspected engine
// container's private bootstrap. It never starts a provider or runs model input.
// Child closure inside the bootstrap precedes export; supervisor fencing remains
// required before persistence. Stdout is private worker custody, never tool/audit
// output. A source fork CAN change this helper, invalidating credential isolation.
const engineCredentialExportScript = `const net=require('node:net');
const magic=Buffer.from('COMMONROOM-CREDENTIAL-EXPORT-V1\n');
let data=Buffer.alloc(0),done=false;
const socket=net.createConnection('/tmp/commonroom-engine/credential-export.sock');
const timer=setTimeout(fail,10000);
function fail(){if(done)return;done=true;clearTimeout(timer);data.fill(0);socket.destroy();process.exitCode=78;}
socket.on('error',fail);
socket.on('connect',()=>socket.end(magic));
socket.on('data',part=>{if(done)return;if(data.length+part.length>magic.length+4+65536){fail();return;}data=Buffer.concat([data,part]);});
socket.on('end',()=>{if(done)return;const offset=magic.length;
if(data.length<offset+6||!data.subarray(0,offset).equals(magic)){fail();return;}
const n=data.readUInt32BE(offset);if(n<2||n>65536||data.length!==offset+4+n){fail();return;}
done=true;clearTimeout(timer);process.stdout.on('error',()=>{process.exitCode=78;});
process.stdout.write(data.subarray(offset+4),()=>{data.fill(0);socket.destroy();});});
socket.on('close',()=>{if(!done)fail();});`

// ExportCredential consumes one attempt after Attach and a running-policy check.
// It stops the provider child via the private bootstrap and returns sensitive
// bounded bytes only to trusted worker custody. No retry/adoption/host fallback.
func (r *EngineContainerRuntime) ExportCredential(ctx context.Context, id string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	child, done, err := r.context(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	if id != r.id || !r.running || !r.verified || !r.attached || r.credentialExported {
		return nil, ErrRejected
	}
	r.credentialExported = true
	child, cancel := context.WithTimeout(child, 12*time.Second)
	defer cancel()
	inspection, err := r.inspect(child)
	if err != nil || r.verify(inspection, true) != nil {
		return nil, ErrRejected
	}
	output := &boundedOutput{cancel: cancel, maxBytes: 65536}
	err = r.runner.Run(child, []string{"exec", "--user", "1000:1000", "--workdir", "/tmp", id, "/usr/local/bin/node", "-e", engineCredentialExportScript}, nil, output)
	raw, overflow := output.snapshot()
	output.mu.Lock()
	clear(output.buffer.Bytes())
	output.buffer.Reset()
	output.mu.Unlock()
	if err != nil || overflow || child.Err() != nil || len(raw) < 2 {
		clear(raw)
		return nil, ErrExecution
	}
	inspection, err = r.inspect(child)
	if err != nil || r.verify(inspection, true) != nil || child.Err() != nil {
		clear(raw)
		return nil, ErrRejected
	}
	return raw, nil
}
