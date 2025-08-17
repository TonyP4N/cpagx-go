package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/streadway/amqp"
)

// MessageQueueService 消息队列服务
type MessageQueueService struct {
	conn    *amqp.Connection
	channel *amqp.Channel
	queue   string
}

// TaskMessage 任务消息结构
type TaskMessage struct {
	TaskID     string                 `json:"task_id"`
	Type       string                 `json:"type"`
	Data       map[string]interface{} `json:"data"`
	CreatedAt  time.Time              `json:"created_at"`
	Priority   int                    `json:"priority"`
	RetryCount int                    `json:"retry_count"`
	MaxRetries int                    `json:"max_retries"`
}

// NewMessageQueueService 创建消息队列服务
func NewMessageQueueService(rabbitMQURL string, queueName string) (*MessageQueueService, error) {
	conn, err := amqp.Dial(rabbitMQURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to RabbitMQ: %v", err)
	}

	ch, err := conn.Channel()
	if err != nil {
		return nil, fmt.Errorf("failed to open channel: %v", err)
	}

	// 声明队列
	_, err = ch.QueueDeclare(
		queueName, // name
		true,      // durable
		false,     // delete when unused
		false,     // exclusive
		false,     // no-wait
		nil,       // arguments
	)
	if err != nil {
		return nil, fmt.Errorf("failed to declare queue: %v", err)
	}

	// 声明死信队列
	dlq, err := ch.QueueDeclare(
		queueName+"_dlq", // name
		true,             // durable
		false,            // delete when unused
		false,            // exclusive
		false,            // no-wait
		nil,              // arguments
	)
	if err != nil {
		return nil, fmt.Errorf("failed to declare dead letter queue: %v", err)
	}

	// 设置队列参数，包含死信队列
	args := amqp.Table{
		"x-dead-letter-exchange":    "",
		"x-dead-letter-routing-key": dlq.Name,
		"x-message-ttl":             int32(24 * 60 * 60 * 1000), // 24小时TTL
	}

	// 重新声明主队列，包含死信队列配置
	_, err = ch.QueueDeclare(
		queueName, // name
		true,      // durable
		false,     // delete when unused
		false,     // exclusive
		false,     // no-wait
		args,      // arguments
	)
	if err != nil {
		return nil, fmt.Errorf("failed to redeclare queue with DLQ: %v", err)
	}

	return &MessageQueueService{
		conn:    conn,
		channel: ch,
		queue:   queueName,
	}, nil
}

// PublishTask 发布任务到队列
func (mqs *MessageQueueService) PublishTask(task *TaskMessage) error {
	body, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("failed to marshal task: %v", err)
	}

	// 设置消息属性
	headers := amqp.Table{
		"retry_count": task.RetryCount,
		"max_retries": task.MaxRetries,
	}

	err = mqs.channel.Publish(
		"",        // exchange
		mqs.queue, // routing key
		false,     // mandatory
		false,     // immediate
		amqp.Publishing{
			DeliveryMode: amqp.Persistent,
			ContentType:  "application/json",
			Body:         body,
			Headers:      headers,
			Priority:     uint8(task.Priority),
			Timestamp:    time.Now(),
		},
	)
	if err != nil {
		return fmt.Errorf("failed to publish message: %v", err)
	}

	log.Printf("Task published to queue: %s", task.TaskID)
	return nil
}

// ConsumeTasks 消费任务
func (mqs *MessageQueueService) ConsumeTasks(handler func(*TaskMessage) error) error {
	msgs, err := mqs.channel.Consume(
		mqs.queue, // queue
		"",        // consumer
		false,     // auto-ack
		false,     // exclusive
		false,     // no-local
		false,     // no-wait
		nil,       // args
	)
	if err != nil {
		return fmt.Errorf("failed to register consumer: %v", err)
	}

	go func() {
		for msg := range msgs {
			var task TaskMessage
			if err := json.Unmarshal(msg.Body, &task); err != nil {
				log.Printf("Failed to unmarshal message: %v", err)
				msg.Nack(false, false)
				continue
			}

			// 处理任务
			if err := handler(&task); err != nil {
				log.Printf("Task processing failed: %v", err)

				// 检查重试次数
				retryCount := 0
				if msg.Headers["retry_count"] != nil {
					if count, ok := msg.Headers["retry_count"].(int32); ok {
						retryCount = int(count)
					}
				}

				maxRetries := 3
				if msg.Headers["max_retries"] != nil {
					if max, ok := msg.Headers["max_retries"].(int32); ok {
						maxRetries = int(max)
					}
				}

				if retryCount < maxRetries {
					// 重新发布到队列，增加重试次数
					task.RetryCount = retryCount + 1
					if err := mqs.PublishTask(&task); err != nil {
						log.Printf("Failed to republish task: %v", err)
					}
					msg.Ack(false)
				} else {
					// 超过最大重试次数，拒绝消息（会进入死信队列）
					log.Printf("Task %s exceeded max retries, sending to DLQ", task.TaskID)
					msg.Nack(false, false)
				}
			} else {
				// 任务处理成功
				msg.Ack(false)
				log.Printf("Task %s processed successfully", task.TaskID)
			}
		}
	}()

	return nil
}

// GetQueueStats 获取队列统计信息
func (mqs *MessageQueueService) GetQueueStats() (map[string]interface{}, error) {
	queue, err := mqs.channel.QueueInspect(mqs.queue)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect queue: %v", err)
	}

	dlq, err := mqs.channel.QueueInspect(mqs.queue + "_dlq")
	if err != nil {
		return nil, fmt.Errorf("failed to inspect DLQ: %v", err)
	}

	return map[string]interface{}{
		"queue_name":    queue.Name,
		"messages":      queue.Messages,
		"consumers":     queue.Consumers,
		"dlq_messages":  dlq.Messages,
		"dlq_consumers": dlq.Consumers,
		"last_updated":  time.Now().Unix(),
	}, nil
}

// Close 关闭连接
func (mqs *MessageQueueService) Close() error {
	if mqs.channel != nil {
		if err := mqs.channel.Close(); err != nil {
			return fmt.Errorf("failed to close channel: %v", err)
		}
	}
	if mqs.conn != nil {
		if err := mqs.conn.Close(); err != nil {
			return fmt.Errorf("failed to close connection: %v", err)
		}
	}
	return nil
}

// HealthCheck 健康检查
func (mqs *MessageQueueService) HealthCheck(ctx context.Context) error {
	if mqs.conn == nil || mqs.conn.IsClosed() {
		return fmt.Errorf("RabbitMQ connection is closed")
	}

	// Channel没有IsClosed方法，通过检查连接状态来判断
	if mqs.channel == nil {
		return fmt.Errorf("RabbitMQ channel is nil")
	}

	return nil
}
