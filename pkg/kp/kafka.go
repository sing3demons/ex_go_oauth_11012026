package kp

import (
	"context"
	"fmt"

	"github.com/sing3demons/oauth/kp/internal/config"
	"github.com/sing3demons/oauth/kp/pkg/kafka"
	"github.com/sing3demons/oauth/kp/pkg/logger"
)

type KafkaClient struct {
	kafkaClient   kafka.Client
	subscriptions map[string]MyHandler
	config        *config.AppConfig
	log           logger.ILogger
}

func newKafkaClient(kafkaClient kafka.Client) *KafkaClient {
	return &KafkaClient{
		kafkaClient:   kafkaClient,
		subscriptions: make(map[string]MyHandler),
	}
}

func (kc *KafkaClient) startKafkaConsumer(ctx context.Context, topic string, handler MyHandler) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			err := kc.handleSubscription(ctx, topic, handler)
			if err != nil {
				fmt.Errorf("error in subscription for topic %s: %v", topic, err)
			}
		}
	}
}

func (kc *KafkaClient) handleSubscription(ctx context.Context, topic string, handler MyHandler) error {
	msg, err := kc.kafkaClient.Subscribe(ctx, topic)
	if err != nil {
		// kc.log.appLog.Errorf("error subscribing to topic %s: %v", topic, err)
		return err
	}

	if msg == nil {
		return nil
	}

	msgCtx := newMuxContext(nil, nil, kc.config, kc.log)
	err = func(ctx *Ctx) error {
		defer func() {
			// panicRecovery(recover(), kc.log.appLog)
			recover()
		}()

		handler(ctx)
		return nil
	}(msgCtx.(*Ctx))

	if err != nil {
		fmt.Errorf("error handling message from topic %s: %v", topic, err)
		return nil
	}

	if msg.Committer != nil {
		msg.Commit()
	}

	return nil
}
