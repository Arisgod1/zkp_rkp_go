package audit

import "context"

type Publisher interface {
	Publish(ctx context.Context, e Event) error
}
