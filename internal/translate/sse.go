package translate

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
)

// MaxSSELineBytes caps a single SSE line to prevent unbounded memory growth
// while comfortably exceeding bufio.Scanner's 64 KiB ceiling for large tool calls,
// extended thinking blocks, and OpenAI response.completed envelopes.
const MaxSSELineBytes = 16 * 1024 * 1024 // 16 MiB

// ErrSSELineTooLong is returned when a single SSE line exceeds MaxSSELineBytes.
var ErrSSELineTooLong = errors.New("translate: sse line exceeds maximum size")

// SSEEvent represents a single decoded Server-Sent Event frame.
type SSEEvent struct {
	Event string
	Data  []byte
}

// ReadSSEEvent reads the next Server-Sent Event frame from r using bufio.Reader
// (never bufio.Scanner, avoiding the 64 KiB token limit).
//
// It handles both \r\n and \n endings, ignores comment lines starting with ':',
// joins multiple data: lines with '\n', and strips at most one leading space
// after the field colon per the WHATWG SSE specification.
//
// On clean EOF after all events have been read, it returns io.EOF.
func ReadSSEEvent(r *bufio.Reader) (SSEEvent, error) {
	var (
		eventName string
		dataBuf   bytes.Buffer
		hasData   bool
		hasEvent  bool
	)

	for {
		line, err := readLineLimited(r, MaxSSELineBytes)
		if err != nil && !errors.Is(err, io.EOF) {
			return SSEEvent{}, err
		}

		// Trim trailing \r\n or \n.
		trimmed := bytes.TrimRight(line, "\r\n")

		if len(trimmed) == 0 {
			if hasData || hasEvent {
				return SSEEvent{
					Event: eventName,
					Data:  bytes.Clone(dataBuf.Bytes()),
				}, nil
			}
			if errors.Is(err, io.EOF) {
				return SSEEvent{}, io.EOF
			}
			continue
		}

		// Skip SSE comments.
		if trimmed[0] != ':' {
			field, value := parseSSEField(trimmed)
			switch field {
			case "event":
				eventName = value
				hasEvent = true
			case "data":
				if hasData {
					dataBuf.WriteByte('\n')
				}
				dataBuf.WriteString(value)
				hasData = true
			}
		}

		if errors.Is(err, io.EOF) {
			if hasData || hasEvent {
				return SSEEvent{
					Event: eventName,
					Data:  bytes.Clone(dataBuf.Bytes()),
				}, nil
			}
			return SSEEvent{}, io.EOF
		}
	}
}

// WriteSSEEvent writes a single SSE frame to w.
// If eventName is non-empty, an "event:" line precedes the "data:" line(s).
func WriteSSEEvent(w io.Writer, eventName string, data []byte) error {
	var buf bytes.Buffer
	if eventName != "" {
		buf.WriteString("event: ")
		buf.WriteString(eventName)
		buf.WriteByte('\n')
	}
	if len(data) == 0 {
		buf.WriteString("data: \n")
	} else {
		lines := bytes.Split(data, []byte("\n"))
		for _, line := range lines {
			buf.WriteString("data: ")
			buf.Write(line)
			buf.WriteByte('\n')
		}
	}
	buf.WriteByte('\n')
	_, err := w.Write(buf.Bytes())
	return err
}

// ReadLineLimited reads up to a '\n' byte from r, enforcing maxBytes to avoid
// OOM on malformed streams while supporting multi-megabyte SSE frames.
func ReadLineLimited(r *bufio.Reader, maxBytes int) ([]byte, error) {
	return readLineLimited(r, maxBytes)
}

func readLineLimited(r *bufio.Reader, maxBytes int) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(line)+len(chunk) > maxBytes {
			return nil, fmt.Errorf("%w (%d bytes)", ErrSSELineTooLong, maxBytes)
		}
		line = append(line, chunk...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return line, err
	}
}

func parseSSEField(line []byte) (field, value string) {
	colon := bytes.IndexByte(line, ':')
	if colon < 0 {
		return string(line), ""
	}
	field = string(line[:colon])
	val := line[colon+1:]
	if len(val) > 0 && val[0] == ' ' {
		val = val[1:]
	}
	return field, strings.Clone(string(val))
}
