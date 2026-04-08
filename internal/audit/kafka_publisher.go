package audit

import (
	"context"
	"encoding/json"
	"time"

	"github.com/segmentio/kafka-go"
)

type KafkaPublisher struct {
	writer *kafka.Writer
	topic  string
}

type KafkaPublisherConfig struct {
	Brokers      []string
	Topic        string
	ClientID     string
	WriteTimeout time.Duration
}

func NewKafkaPublisher(cfg KafkaPublisherConfig) *KafkaPublisher {
	w := &kafka.Writer{
		Addr:         kafka.TCP(cfg.Brokers...),
		Topic:        cfg.Topic,
		Balancer:     &kafka.LeastBytes{},
		RequiredAcks: kafka.RequireOne,
		Async:        false, // 这里保持同步；异步在外层 worker 做
		Transport: &kafka.Transport{
			ClientID: cfg.ClientID,
		},
		WriteTimeout: cfg.WriteTimeout,
	}
	return &KafkaPublisher{
		writer: w,
		topic:  cfg.Topic,
	}
}

func (p *KafkaPublisher) Publish(ctx context.Context, e Event) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	msg := kafka.Message{
		Key:   []byte(e.EventType),
		Value: b,
		Time:  time.Now().UTC(),
	}
	return p.writer.WriteMessages(ctx, msg)
}

func (p *KafkaPublisher) Close() error {
	return p.writer.Close()
}
