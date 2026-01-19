package kafka

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"
)

var (
	ErrConsumerGroupNotProvided = errors.New("consumer group id not provided")
	errFailedToConnectBrokers   = errors.New("failed to connect to any kafka brokers")
	errBrokerNotProvided        = errors.New("kafka broker address not provided")
	errPublisherNotConfigured   = errors.New("publisher not configured or topic is empty")
	errClientNotConnected       = errors.New("kafka client not connected")
	errNoActiveConnections      = errors.New("no active connections to brokers")
)

const (
	DefaultBatchSize    = 100
	DefaultBatchBytes   = 1048576
	DefaultBatchTimeout = 1000
	defaultRetryTimeout = 10 * time.Second
)

type Config struct {
	Brokers          []string
	ConsumerGroupID  string
	OffSet           int
	BatchSize        int
	BatchBytes       int
	BatchTimeout     int
	SASLMechanism    string
	SASLUser         string
	SASLPassword     string
	SecurityProtocol string
	TLS              TLSConfig
}

type TLSConfig struct {
	CertFile, KeyFile, CACertFile string
	InsecureSkipVerify            bool
}

type kafkaClient struct {
	dialer *kafka.Dialer
	conn   *multiConn
	writer Writer
	reader map[string]Reader
	mu     sync.RWMutex
	config Config
}

type multiConn struct {
	conns  []Connection
	dialer *kafka.Dialer
	mu     sync.RWMutex
}

type kafkaMessage struct {
	msg    *kafka.Message
	reader Reader
}

func New(conf *Config) *kafkaClient {
	if conf == nil || len(conf.Brokers) == 0 || conf.BatchSize <= 0 || conf.BatchBytes <= 0 || conf.BatchTimeout <= 0 {
		return nil
	}
	if conf.SecurityProtocol == "" {
		conf.SecurityProtocol = "PLAINTEXT"
	}
	client := &kafkaClient{config: *conf, reader: make(map[string]Reader)}
	if err := client.initialize(context.Background()); err != nil {
		go client.retryConnect()
	}
	return client
}

func (k *kafkaClient) initialize(ctx context.Context) error {
	dialer, err := k.setupDialer()
	if err != nil {
		return err
	}
	conns, err := connectToBrokers(ctx, k.config.Brokers, dialer)
	if err != nil {
		return err
	}
	k.dialer = dialer
	k.conn = &multiConn{conns: conns, dialer: dialer}
	k.writer = kafka.NewWriter(kafka.WriterConfig{
		Brokers: k.config.Brokers, Dialer: dialer,
		BatchSize: k.config.BatchSize, BatchBytes: k.config.BatchBytes,
		BatchTimeout: time.Duration(k.config.BatchTimeout),
	})
	return nil
}

func (k *kafkaClient) setupDialer() (*kafka.Dialer, error) {
	dialer := &kafka.Dialer{Timeout: 10 * time.Second, DualStack: true}
	protocol := strings.ToUpper(k.config.SecurityProtocol)

	if protocol == "SASL_PLAINTEXT" || protocol == "SASL_SSL" {
		mech, err := getSASLMechanism(k.config.SASLMechanism, k.config.SASLUser, k.config.SASLPassword)
		if err != nil {
			return nil, err
		}
		dialer.SASLMechanism = mech
	}
	if protocol == "SSL" || protocol == "SASL_SSL" {
		tlsConfig, err := createTLSConfig(&k.config.TLS)
		if err != nil {
			return nil, err
		}
		dialer.TLS = tlsConfig
	}
	return dialer, nil
}

func (k *kafkaClient) retryConnect() {
	for {
		time.Sleep(defaultRetryTimeout)
		if err := k.initialize(context.Background()); err != nil {
			fmt.Printf("Retrying connection to Kafka at %v...\n", k.config.Brokers)
			continue
		}
		return
	}
}

func (k *kafkaClient) isConnected() bool {
	return k.conn != nil && k.conn.Controller() != nil
}

func connectToBrokers(ctx context.Context, brokers []string, dialer *kafka.Dialer) ([]Connection, error) {
	var conns []Connection
	for _, broker := range brokers {
		if conn, err := dialer.DialContext(ctx, "tcp", broker); err == nil {
			conns = append(conns, conn)
		}
	}
	if len(conns) == 0 {
		return nil, errFailedToConnectBrokers
	}
	return conns, nil
}

func getSASLMechanism(mechanism, username, password string) (sasl.Mechanism, error) {
	switch strings.ToUpper(mechanism) {
	case "PLAIN":
		return plain.Mechanism{Username: username, Password: password}, nil
	case "SCRAM-SHA-256":
		return scram.Mechanism(scram.SHA256, username, password)
	case "SCRAM-SHA-512":
		return scram.Mechanism(scram.SHA512, username, password)
	default:
		return nil, fmt.Errorf("unsupported SASL mechanism: %s", mechanism)
	}
}

func createTLSConfig(cfg *TLSConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify}
	if cfg.CACertFile != "" {
		caCert, err := os.ReadFile(cfg.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = pool
	}
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client cert: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	return tlsConfig, nil
}

// multiConn methods
func (m *multiConn) Controller() *kafka.Broker {
	for _, conn := range m.conns {
		if conn != nil {
			if broker, err := conn.Controller(); err == nil {
				return &broker
			}
		}
	}
	return nil
}

func (m *multiConn) withController(fn func(Connection) error) error {
	controller := m.Controller()
	if controller == nil {
		return errNoActiveConnections
	}
	addr := net.JoinHostPort(controller.Host, strconv.Itoa(controller.Port))
	resolved, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, conn := range m.conns {
		if conn == nil {
			continue
		}
		if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			if tcpAddr.IP.Equal(resolved.IP) && tcpAddr.Port == resolved.Port {
				return fn(conn)
			}
		}
	}
	conn, err := m.dialer.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		return err
	}
	m.conns = append(m.conns, conn)
	return fn(conn)
}

func (m *multiConn) CreateTopics(topics ...kafka.TopicConfig) error {
	return m.withController(func(c Connection) error { return c.CreateTopics(topics...) })
}

func (m *multiConn) DeleteTopics(topics ...string) error {
	return m.withController(func(c Connection) error { return c.DeleteTopics(topics...) })
}

func (m *multiConn) Close() error {
	var err error
	for _, conn := range m.conns {
		if conn != nil {
			err = errors.Join(err, conn.Close())
		}
	}
	return err
}

// kafkaClient public methods
func (k *kafkaClient) CreateTopic(_ context.Context, name string) error {
	return k.conn.CreateTopics(kafka.TopicConfig{Topic: name, NumPartitions: 1, ReplicationFactor: 1})
}

func (k *kafkaClient) DeleteTopic(_ context.Context, name string) error {
	return k.conn.DeleteTopics(name)
}

func (k *kafkaClient) Publish(ctx context.Context, topic string, message []byte) error {
	if k.writer == nil || topic == "" {
		return errPublisherNotConfigured
	}
	return k.writer.WriteMessages(ctx, kafka.Message{Topic: topic, Value: message, Time: time.Now()})
}

func (k *kafkaClient) Subscribe(ctx context.Context, topic string) (*Message, error) {
	if !k.isConnected() {
		time.Sleep(defaultRetryTimeout)
		return nil, errClientNotConnected
	}
	if k.config.ConsumerGroupID == "" {
		return nil, ErrConsumerGroupNotProvided
	}

	k.mu.Lock()
	if k.reader[topic] == nil {
		k.reader[topic] = kafka.NewReader(kafka.ReaderConfig{
			GroupID: k.config.ConsumerGroupID, Brokers: k.config.Brokers, Topic: topic,
			MinBytes: 10e3, MaxBytes: 10e6, Dialer: k.dialer, StartOffset: int64(k.config.OffSet),
		})
	}
	reader := k.reader[topic]
	k.mu.Unlock()

	msg, err := reader.FetchMessage(ctx)
	if err != nil {
		return nil, err
	}
	return &Message{
		ctx: ctx, Topic: topic, Value: msg.Value,
		Committer: &kafkaMessage{msg: &msg, reader: reader},
	}, nil
}

func (k *kafkaClient) Close() (err error) {
	for _, r := range k.reader {
		err = errors.Join(err, r.Close())
	}
	if k.writer != nil {
		err = errors.Join(err, k.writer.Close())
	}
	if k.conn != nil {
		err = errors.Join(err, k.conn.Close())
	}
	return
}

func (km *kafkaMessage) Commit() {
	if km.reader != nil {
		_ = km.reader.CommitMessages(context.Background(), *km.msg)
	}
}

// Interfaces
type Reader interface {
	FetchMessage(ctx context.Context) (kafka.Message, error)
	CommitMessages(ctx context.Context, msgs ...kafka.Message) error
	Close() error
}

type Writer interface {
	WriteMessages(ctx context.Context, msg ...kafka.Message) error
	Close() error
}

type Connection interface {
	Controller() (kafka.Broker, error)
	CreateTopics(...kafka.TopicConfig) error
	DeleteTopics(...string) error
	RemoteAddr() net.Addr
	Close() error
}

type Client interface {
	Publish(ctx context.Context, topic string, message []byte) error
	Subscribe(ctx context.Context, topic string) (*Message, error)
	CreateTopic(ctx context.Context, name string) error
	DeleteTopic(ctx context.Context, name string) error
	Close() error
}

type Committer interface{ Commit() }

// Message
type Message struct {
	ctx      context.Context
	Topic    string
	Value    []byte
	MetaData any
	Committer
}

func (m *Message) Context() context.Context {
	if m.ctx == nil {
		return context.Background()
	}
	return m.ctx
}

func (m *Message) Body() (string, error) {
	if len(m.Value) == 0 {
		return "", errors.New("message value is empty")
	}
	return string(m.Value), nil
}
