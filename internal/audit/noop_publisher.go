package audit

import "context"

type NoopPublisher struct{}

func NewNoopPublisher() *NoopPublisher {
	return &NoopPublisher{}
}

func (n *NoopPublisher) Publish(ctx context.Context, e Event) error {
	// MVP阶段先不做任何事，保证主流程稳定
	return nil
}
