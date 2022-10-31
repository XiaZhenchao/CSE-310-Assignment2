        if flowPort[i] == tcp.sport and CheckSEQ != tcp.seq:
            CheckSEQ = tcp.seq
            ResendStartTime = ts
        elif flowPort[i] == tcp.sport and CheckSEQ == tcp.seq:
            ResendEndTime = ts
            CounterfoRetransmission+=1
            if ResendEndTime - ResendStartTime <= rto:
                CounterforDuplicateACK =  CounterforDuplicateACK+1