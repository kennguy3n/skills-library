// Package mcp implements the Model Context Protocol server that backs
// the skills-mcp binary. The transport is JSON-RPC 2.0 over stdio with
// one request per line.
package mcp

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/kennguy3n/skills-library/cmd/skills-mcp/internal/tools"
)

// Server is the JSON-RPC dispatcher. It owns one Library and exposes the
// 4 Skills Library tools as MCP tools.
type Server struct {
	lib *tools.Library
}

// NewServer wires a Server up against the library rooted at root.
func NewServer(root string) (*Server, error) {
	lib, err := tools.NewLibrary(root)
	if err != nil {
		return nil, err
	}
	return &Server{lib: lib}, nil
}

// JSON-RPC 2.0 wire types.
type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

// Serve reads JSON-RPC messages from r, dispatches them, and writes
// responses to w. One message per line. Notifications (no id) get no
// response.
func (s *Server) Serve(r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		resp := s.HandleLine(line)
		if resp == nil {
			continue
		}
		out, err := json.Marshal(resp)
		if err != nil {
			return fmt.Errorf("marshal response: %w", err)
		}
		out = append(out, '\n')
		if _, err := w.Write(out); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// HandleLine parses one JSON-RPC line and returns the response (or nil
// for a notification). Exported so tests can drive the dispatcher
// without spinning up a real reader/writer pair.
func (s *Server) HandleLine(line []byte) *response {
	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		return errorResponse(nil, codeParseError, "parse error: "+err.Error())
	}
	if req.JSONRPC != "2.0" {
		return errorResponse(req.ID, codeInvalidRequest, "jsonrpc must be 2.0")
	}
	// Notifications: no id, no response.
	isNotification := len(req.ID) == 0 || string(req.ID) == "null"
	resp := s.dispatch(&req)
	if isNotification {
		return nil
	}
	resp.ID = req.ID
	return resp
}

func (s *Server) dispatch(req *request) *response {
	switch req.Method {
	case "initialize":
		return successResponse(req.ID, map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"serverInfo": map[string]string{
				"name":    "skills-mcp",
				"version": "0.1.0",
			},
			"capabilities": map[string]interface{}{
				"tools": map[string]interface{}{},
			},
		})
	case "tools/list":
		return successResponse(req.ID, map[string]interface{}{
			"tools": toolDefinitions(),
		})
	case "tools/call":
		return s.handleToolsCall(req)
	default:
		return errorResponse(req.ID, codeMethodNotFound, "method not found: "+req.Method)
	}
}

func (s *Server) handleToolsCall(req *request) *response {
	var p struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return errorResponse(req.ID, codeInvalidParams, "invalid params: "+err.Error())
	}
	if p.Arguments == nil {
		p.Arguments = map[string]interface{}{}
	}
	result, err := s.invokeTool(p.Name, p.Arguments)
	if err != nil {
		if errors.Is(err, errToolNotFound) {
			return errorResponse(req.ID, codeMethodNotFound, err.Error())
		}
		return errorResponse(req.ID, codeInternalError, err.Error())
	}
	body, err := json.Marshal(result)
	if err != nil {
		return errorResponse(req.ID, codeInternalError, "marshal tool result: "+err.Error())
	}
	return successResponse(req.ID, map[string]interface{}{
		"content": []map[string]string{
			{"type": "text", "text": string(body)},
		},
		"structuredContent": result,
	})
}

var errToolNotFound = errors.New("tool not found")

func (s *Server) invokeTool(name string, args map[string]interface{}) (interface{}, error) {
	switch name {
	case "lookup_vulnerability":
		return s.lib.LookupVulnerability(
			stringArg(args, "package"),
			stringArg(args, "ecosystem"),
			stringArg(args, "version"),
		)
	case "check_secret_pattern":
		return s.lib.CheckSecretPattern(stringArg(args, "text"))
	case "get_skill":
		return s.lib.GetSkill(
			stringArg(args, "skill_id"),
			stringArg(args, "budget"),
		)
	case "search_skills":
		return s.lib.SearchSkills(stringArg(args, "query"))
	}
	return nil, fmt.Errorf("%w: %s", errToolNotFound, name)
}

func stringArg(args map[string]interface{}, key string) string {
	v, ok := args[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

func successResponse(id json.RawMessage, result interface{}) *response {
	return &response{JSONRPC: "2.0", ID: id, Result: result}
}

func errorResponse(id json.RawMessage, code int, msg string) *response {
	return &response{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}
