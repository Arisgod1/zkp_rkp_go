package audit

import (
	"context"
	"log"
	"sync"
	"time"
)

type AsyncPublisher struct {
	inner        Publisher
	queue        chan Event
	writeTimeout time.Duration
	wg           sync.WaitGroup
	stopOnce     sync.Once
	stopCh       chan struct{}
}

func NewAsyncPublisher(inner Publisher, queueSize int, writeTimeout time.Duration) *AsyncPublisher {
	if queueSize <= 0 {
		queueSize = 1000
	}
	p := &AsyncPublisher{
		inner:        inner,
		queue:        make(chan Event, queueSize),
		writeTimeout: writeTimeout,
		stopCh:       make(chan struct{}),
	}
	p.wg.Add(1)
	go p.worker()
	return p
}

func (p *AsyncPublisher) Publish(ctx context.Context, e Event) error {
	select {
	case p.queue <- e:
		return nil
	default:
		// 队列满：丢弃并记日志（不影响主流程）
		log.Printf("[audit] queue full, drop event_type=%s event_id=%s", e.EventType, e.EventID)
		return nil
	}
}

func (p *AsyncPublisher) worker() {
	defer p.wg.Done()
	for {
		select {
		case <-p.stopCh:
			// 尝试清空队列
			for {
				select {
				case e := <-p.queue:
					p.writeOne(e)
				default:
					return
				}
			}
		case e := <-p.queue:
			p.writeOne(e)
		}
	}
}

func (p *AsyncPublisher) writeOne(e Event) {
	ctx, cancel := context.WithTimeout(context.Background(), p.writeTimeout)
	defer cancel()
	if err := p.inner.Publish(ctx, e); err != nil {
		log.Printf("[audit] publish failed event_type=%s event_id=%s err=%v", e.EventType, e.EventID, err)
	}
}

func (p *AsyncPublisher) Close() {
	p.stopOnce.Do(func() {
		close(p.stopCh)
		p.wg.Wait()
	})
}
