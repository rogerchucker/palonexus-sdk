//go:build darwin || linux

package reconcile

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	p "github.com/rogerchucker/palonexus-sdk/guard/pkg/protocol"
	"golang.org/x/sys/unix"
)

const envelopeVersion = 1
const transitionReserveBytes = int64(3 * maxRecordBytesDefault)
const maxTransactionBytes = int64(2*maxRecordBytesDefault + 32*1024)

type diskEnvelope struct {
	Version      int                    `json:"version"`
	TenantHash   string                 `json:"tenantHash"`
	SubjectHash  string                 `json:"subjectHash"`
	EvidenceHash p.SHA256Digest         `json:"evidenceHash"`
	Record       p.ReconciliationRecord `json:"record"`
	HoldClass    DeliveryErrorClass     `json:"holdClass,omitempty"`
	dev          uint64
	ino          uint64
	digest       [32]byte
}

type checkpointEntry struct {
	ReconciliationID p.ReconciliationID `json:"reconciliationId"`
	EvidenceHash     p.SHA256Digest     `json:"evidenceHash"`
}
type batchCheckpoint struct {
	Version              int                        `json:"version"`
	BatchID              p.BatchID                  `json:"batchId"`
	ExpectedNextSequence p.JSONInteger              `json:"expectedNextSequence"`
	CompletedPrefix      map[string]checkpointEntry `json:"completedPrefix"`
	dev                  uint64
	ino                  uint64
	digest               [32]byte
}

type batchTransaction struct {
	Version             int             `json:"version"`
	Operation           string          `json:"operation"`
	RecordName          string          `json:"recordName"`
	CheckpointName      string          `json:"checkpointName"`
	OldRecordDigest     string          `json:"oldRecordDigest"`
	OldCheckpointDigest string          `json:"oldCheckpointDigest"`
	NewEnvelope         diskEnvelope    `json:"newEnvelope"`
	NewCheckpoint       batchCheckpoint `json:"newCheckpoint"`
}

type fileSnapshot struct {
	dev    uint64
	ino    uint64
	digest [32]byte
}

type doneTombstone struct {
	Version       int    `json:"version"`
	Operation     string `json:"operation"`
	RecordName    string `json:"recordName"`
	JournalDigest string `json:"journalDigest"`
}

type unixQueue struct {
	rootFD                  int
	root                    string
	rootDev                 uint64
	rootIno                 uint64
	config                  Config
	lifecycle               sync.RWMutex
	mu                      sync.Mutex
	closed                  bool
	needsRecovery           bool
	afterTransactionRecord  func() error
	afterCheckpointCreate   func() error
	beforeTransactionRemove func(string) error
	afterTransactionRename  func() error
	afterTransactionDirSync func() error
	afterTransactionVerify  func() error
}

var rootCoordinators sync.Map

func openQueue(config Config) (queueImpl, error) {
	if config.Root == "" || !filepath.IsAbs(config.Root) || filepath.Clean(config.Root) == "/" {
		return nil, ErrUnsafePath
	}
	fd, err := openRoot(config.Root)
	if err != nil {
		return nil, err
	}
	var rootStat unix.Stat_t
	if unix.Fstat(fd, &rootStat) != nil {
		unix.Close(fd)
		return nil, ErrUnsafePath
	}
	q := &unixQueue{rootFD: fd, root: config.Root, rootDev: uint64(rootStat.Dev), rootIno: uint64(rootStat.Ino), config: config}
	if err := q.withLock(context.Background(), func() error {
		if err := q.recoverTransactions(context.Background()); err != nil {
			return err
		}
		if err := q.validateAll(); err != nil {
			return err
		}
		if err := q.recoverAllSending(context.Background()); err != nil {
			return err
		}
		if err := q.reconcileCheckpoints(context.Background()); err != nil {
			return err
		}
		return q.validateAllBatchGroups()
	}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return q, nil
}

func openRoot(path string) (int, error) {
	clean := filepath.Clean(path)
	if info, err := os.Lstat(clean); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return -1, ErrUnsafePath
	}
	// macOS exposes /var as a system-owned compatibility symlink to /private/var.
	// Resolve existing ancestors only after rejecting a symlink at the caller's
	// queue root itself; every subsequently opened component still uses NOFOLLOW.
	if resolved, err := filepath.EvalSymlinks(filepath.Dir(clean)); err == nil {
		clean = filepath.Join(resolved, filepath.Base(clean))
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, ErrUnsafePath
	}
	for index, part := range strings.Split(strings.TrimPrefix(clean, "/"), "/") {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if errors.Is(e, unix.ENOENT) && index == len(strings.Split(strings.TrimPrefix(clean, "/"), "/"))-1 {
			if e = unix.Mkdirat(fd, part, 0o700); e != nil && !errors.Is(e, unix.EEXIST) {
				unix.Close(fd)
				return -1, ErrUnsafePath
			}
			next, e = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		unix.Close(fd)
		if e != nil {
			return -1, ErrUnsafePath
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Nlink < 1 ||
			(st.Uid != 0 && int(st.Uid) != os.Geteuid()) ||
			(st.Mode&0o022 != 0 && !(st.Uid == 0 && st.Mode&unix.S_ISVTX != 0)) {
			unix.Close(fd)
			return -1, ErrUnsafePath
		}
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || int(st.Uid) != os.Geteuid() || st.Mode&0o077 != 0 {
		unix.Close(fd)
		return -1, ErrUnsafePath
	}
	return fd, nil
}

func (q *unixQueue) close() error {
	q.lifecycle.Lock()
	defer q.lifecycle.Unlock()
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return nil
	}
	q.closed = true
	if unix.Close(q.rootFD) != nil {
		return ErrUnsafePath
	}
	return nil
}

func (q *unixQueue) withLock(ctx context.Context, fn func() error) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	q.lifecycle.RLock()
	defer q.lifecycle.RUnlock()
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return ErrClosed
	}
	fd, err := unix.Dup(q.rootFD)
	q.mu.Unlock()
	if err != nil {
		return ErrClosed
	}
	defer unix.Close(fd)
	for {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return ErrUnsafePath
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Millisecond):
		}
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	key := fmt.Sprintf("%x:%x", q.rootDev, q.rootIno)
	value, _ := rootCoordinators.LoadOrStore(key, &sync.Mutex{})
	coordinator := value.(*sync.Mutex)
	coordinator.Lock()
	defer coordinator.Unlock()
	if !q.rootIdentityMatches() {
		return ErrUnsafePath
	}
	var existing unix.Stat_t
	if statErr := unix.Fstatat(fd, ".queue.lock", &existing, unix.AT_SYMLINK_NOFOLLOW); statErr == nil &&
		(existing.Mode&unix.S_IFMT != unix.S_IFREG || existing.Nlink != 1) {
		return ErrUnsafePath
	} else if statErr != nil && !errors.Is(statErr, unix.ENOENT) {
		return ErrUnsafePath
	}
	lock, err := unix.Openat(fd, ".queue.lock", unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return ErrUnsafePath
	}
	defer unix.Close(lock)
	if err := validateRegular(lock, 0o600); err != nil {
		return err
	}
	for {
		err = unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return ErrUnsafePath
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Millisecond):
		}
	}
	defer unix.Flock(lock, unix.LOCK_UN)
	var before, after unix.Stat_t
	if unix.Fstat(lock, &before) != nil || unix.Fstatat(fd, ".queue.lock", &after, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		before.Dev != after.Dev || before.Ino != after.Ino {
		return ErrUnsafePath
	}
	// Every operation fences journals first, including journals left by another
	// process or by an earlier ambiguous call on this still-open handle.
	if err := q.recoverTransactions(ctx); err != nil {
		return err
	}
	if err := q.validateAll(); err != nil {
		return err
	}
	if err := q.reconcileCheckpoints(ctx); err != nil {
		return err
	}
	if err := q.validateAllBatchGroups(); err != nil {
		return err
	}
	q.clearRecoveryNeeded()
	if err := fn(); err != nil {
		return err
	}
	if !q.rootIdentityMatches() {
		return ErrUnsafePath
	}
	return nil
}

func (q *unixQueue) rootIdentityMatches() bool {
	var stat unix.Stat_t
	return unix.Stat(q.root, &stat) == nil && stat.Mode&unix.S_IFMT == unix.S_IFDIR &&
		uint64(stat.Dev) == q.rootDev && uint64(stat.Ino) == q.rootIno
}

func validateRegular(fd int, mode uint32) error {
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 ||
		int(st.Uid) != os.Geteuid() || uint32(st.Mode)&0o777 != mode {
		return ErrUnsafePath
	}
	return nil
}

func bindingHashes(b Binding) (string, string) {
	t := sha256.Sum256([]byte("tenant\x00" + b.Tenant))
	s := sha256.Sum256([]byte("subject\x00" + b.Subject))
	return hex.EncodeToString(t[:]), hex.EncodeToString(s[:])
}
func recordName(id p.ReconciliationID) string {
	sum := sha256.Sum256([]byte("reconciliation\x00" + string(id)))
	return "recon-" + hex.EncodeToString(sum[:]) + ".json"
}
func checkpointName(id p.BatchID) string {
	sum := sha256.Sum256([]byte("batch-checkpoint\x00" + string(id)))
	return "batch-" + hex.EncodeToString(sum[:]) + ".json"
}
func isRecordName(name string) bool {
	if len(name) != len("recon-")+64+len(".json") || !strings.HasPrefix(name, "recon-") || !strings.HasSuffix(name, ".json") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimSuffix(strings.TrimPrefix(name, "recon-"), ".json"))
	return err == nil
}
func isCheckpointName(name string) bool {
	if len(name) != len("batch-")+64+len(".json") || !strings.HasPrefix(name, "batch-") || !strings.HasSuffix(name, ".json") {
		return false
	}
	return validHex(strings.TrimSuffix(strings.TrimPrefix(name, "batch-"), ".json"))
}

func isTempName(name string) bool {
	return len(name) == len(".tmp-")+32 && strings.HasPrefix(name, ".tmp-") && validHex(name[len(".tmp-"):])
}

func isQuarantineName(name string) bool {
	return len(name) == len(".quarantine-")+64+1+32 && strings.HasPrefix(name, ".quarantine-") &&
		name[len(".quarantine-")+64] == '-' &&
		validHex(name[len(".quarantine-"):len(".quarantine-")+64]) &&
		validHex(name[len(".quarantine-")+65:])
}
func isTransactionName(name string) bool {
	return len(name) == len(".txn-")+32 && strings.HasPrefix(name, ".txn-") && validHex(name[len(".txn-"):])
}

func isDoneTransactionName(name string) bool {
	return len(name) == len(".done-")+32 && strings.HasPrefix(name, ".done-") && validHex(name[len(".done-"):])
}

func validHex(value string) bool {
	_, err := hex.DecodeString(value)
	return err == nil
}

func (q *unixQueue) enqueue(ctx context.Context, b Binding, record p.ReconciliationRecord) error {
	if !validBinding(b) || record.State != p.ReconciliationStatePending || record.AttemptCount != 0 {
		return ErrUnsafeRecord
	}
	wire, err := validateRecord(record, q.config.MaxRecordBytes)
	if err != nil {
		return err
	}
	hash, err := evidenceHash(record)
	if err != nil {
		return err
	}
	return q.withLock(ctx, func() error {
		name := recordName(record.ReconciliationID)
		existing, e := q.read(name)
		if e == nil {
			if existing.TenantHash != hashBinding(b, true) || existing.SubjectHash != hashBinding(b, false) {
				return ErrNotFound
			}
			if existing.EvidenceHash != hash {
				return ErrConflict
			}
			return nil
		}
		if !errors.Is(e, ErrNotFound) {
			return e
		}
		count, _, e := q.usage()
		if e != nil {
			return e
		}
		if count >= q.config.MaxRecords {
			return ErrQueueFull
		}
		checkpoint, createCheckpoint, err := q.validateEnqueueSequence(b, record)
		if err != nil {
			return err
		}
		count, used, e := q.usage()
		if e != nil {
			return e
		}
		env := diskEnvelope{Version: envelopeVersion, TenantHash: hashBinding(b, true), SubjectHash: hashBinding(b, false), EvidenceHash: hash, Record: record}
		document, _ := json.Marshal(env)
		checkpointWire, _ := json.Marshal(checkpoint)
		transaction := batchTransaction{
			Version: envelopeVersion, Operation: "enqueue", RecordName: name,
			CheckpointName: checkpointName(checkpoint.BatchID), NewEnvelope: env, NewCheckpoint: checkpoint,
		}
		if !createCheckpoint {
			transaction.OldCheckpointDigest = hex.EncodeToString(checkpoint.digest[:])
		}
		transactionWire, _ := json.Marshal(transaction)
		required := int64(len(document)+len(transactionWire)) + transitionReserveBytes
		if createCheckpoint {
			required += int64(len(checkpointWire))
		}
		if len(document) > q.config.MaxRecordBytes || len(wire) > q.config.MaxRecordBytes || count >= q.config.MaxRecords ||
			required > q.config.MaxBytes || used > q.config.MaxBytes-required {
			return ErrQueueFull
		}
		return q.commitEnqueueTransaction(ctx, transaction)
	})
}

func (q *unixQueue) validateEnqueueSequence(b Binding, record p.ReconciliationRecord) (batchCheckpoint, bool, error) {
	checkpoint, err := q.readCheckpoint(record.BatchID)
	create := false
	if errors.Is(err, ErrNotFound) {
		if record.BatchSequence != 0 {
			return batchCheckpoint{}, false, ErrConflict
		}
		checkpoint = batchCheckpoint{Version: envelopeVersion, BatchID: record.BatchID, CompletedPrefix: map[string]checkpointEntry{}}
		create = true
	} else if err != nil {
		return batchCheckpoint{}, false, err
	}
	names, err := q.names()
	if err != nil {
		return batchCheckpoint{}, false, err
	}
	maxSequence := p.JSONInteger(-1)
	for _, name := range names {
		item, readErr := q.read(name)
		if readErr != nil {
			return batchCheckpoint{}, false, readErr
		}
		if item.Record.BatchID != record.BatchID {
			continue
		}
		if item.TenantHash != hashBinding(b, true) || item.SubjectHash != hashBinding(b, false) {
			return batchCheckpoint{}, false, ErrConflict
		}
		if item.Record.State == p.ReconciliationStateDiscarded {
			return batchCheckpoint{}, false, ErrConflict
		}
		if item.Record.BatchSequence == record.BatchSequence {
			return batchCheckpoint{}, false, ErrConflict
		}
		if item.Record.BatchSequence > maxSequence {
			maxSequence = item.Record.BatchSequence
		}
	}
	expected := checkpoint.ExpectedNextSequence
	if maxSequence >= expected {
		expected = maxSequence + 1
	}
	if record.BatchSequence != expected {
		return batchCheckpoint{}, false, ErrConflict
	}
	return checkpoint, create, nil
}

func (q *unixQueue) removeCheckpointExact(checkpoint batchCheckpoint) error {
	name := checkpointName(checkpoint.BatchID)
	expected := diskEnvelope{dev: checkpoint.dev, ino: checkpoint.ino, digest: checkpoint.digest}
	if !matchExpectedAt(q.rootFD, name, &expected) {
		return ErrConflict
	}
	if unix.Unlinkat(q.rootFD, name, 0) != nil || unix.Fsync(q.rootFD) != nil {
		return ErrUnsafePath
	}
	return nil
}
func hashBinding(b Binding, tenant bool) string {
	t, s := bindingHashes(b)
	if tenant {
		return t
	}
	return s
}

func (q *unixQueue) get(ctx context.Context, b Binding, id p.ReconciliationID) (p.ReconciliationRecord, error) {
	if !validBinding(b) {
		return p.ReconciliationRecord{}, ErrUnsafeRecord
	}
	var result p.ReconciliationRecord
	err := q.withLock(ctx, func() error {
		env, err := q.read(recordName(id))
		if err != nil {
			return err
		}
		if env.TenantHash != hashBinding(b, true) || env.SubjectHash != hashBinding(b, false) {
			return ErrNotFound
		}
		result = env.Record
		return nil
	})
	return result, err
}

func (q *unixQueue) reconcileCheckpoints(ctx context.Context) error {
	names, err := q.names()
	if err != nil {
		return err
	}
	items := make([]diskEnvelope, 0, len(names))
	for _, name := range names {
		env, readErr := q.read(name)
		if readErr != nil {
			return readErr
		}
		items = append(items, env)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Record.BatchID != items[j].Record.BatchID {
			return items[i].Record.BatchID < items[j].Record.BatchID
		}
		return items[i].Record.BatchSequence < items[j].Record.BatchSequence
	})
	for _, env := range items {
		if env.Record.State != p.ReconciliationStateAcknowledged {
			continue
		}
		checkpoint, readErr := q.readCheckpoint(env.Record.BatchID)
		if readErr != nil {
			return readErr
		}
		key := strconv.FormatInt(int64(env.Record.BatchSequence), 10)
		entry := checkpointEntry{ReconciliationID: env.Record.ReconciliationID, EvidenceHash: env.EvidenceHash}
		if env.Record.BatchSequence < checkpoint.ExpectedNextSequence {
			if checkpoint.CompletedPrefix[key] != entry {
				return ErrCorrupt
			}
			continue
		}
		if env.Record.BatchSequence != checkpoint.ExpectedNextSequence {
			return ErrCorrupt
		}
		previous := checkpoint
		checkpoint.CompletedPrefix[key] = entry
		checkpoint.ExpectedNextSequence++
		if err := q.writeCheckpoint(ctx, checkpoint, &previous); err != nil {
			return err
		}
	}
	return nil
}

func (q *unixQueue) claim(ctx context.Context, b Binding, now time.Time) (p.ReconciliationRecord, error) {
	if !validBinding(b) || now.IsZero() {
		return p.ReconciliationRecord{}, ErrUnsafeRecord
	}
	var result p.ReconciliationRecord
	err := q.withLock(ctx, func() error {
		items, err := q.boundRecords(b)
		if err != nil {
			return err
		}
		sort.Slice(items, func(i, j int) bool {
			if items[i].Record.BatchID != items[j].Record.BatchID {
				return items[i].Record.BatchID < items[j].Record.BatchID
			}
			if items[i].Record.BatchSequence != items[j].Record.BatchSequence {
				return items[i].Record.BatchSequence < items[j].Record.BatchSequence
			}
			return items[i].Record.ReconciliationID < items[j].Record.ReconciliationID
		})
		for start := 0; start < len(items); {
			end := start + 1
			for end < len(items) && items[end].Record.BatchID == items[start].Record.BatchID {
				end++
			}
			if err := q.validateBatchGroup(items[start:end]); err != nil {
				return err
			}
			start = end
		}
		foundBlocked := false
		blockedBatches := make(map[p.BatchID]bool)
		for _, env := range items {
			r := env.Record
			if env.HoldClass != "" {
				foundBlocked = true
				blockedBatches[r.BatchID] = true
				continue
			}
			if blockedBatches[r.BatchID] {
				foundBlocked = true
				continue
			}
			if r.State == p.ReconciliationStateSending {
				foundBlocked = true
				blockedBatches[r.BatchID] = true
				continue
			}
			if r.State == p.ReconciliationStateRetryWait {
				due, e := parseTime(*r.NextAttemptAt)
				if e != nil {
					return e
				}
				if now.Before(due) {
					foundBlocked = true
					blockedBatches[r.BatchID] = true
					continue
				}
			} else if r.State == p.ReconciliationStatePending && r.DeliveryDisposition != p.DeliveryDispositionAutomatic {
				foundBlocked = true
				blockedBatches[r.BatchID] = true
				continue
			} else if r.State != p.ReconciliationStatePending {
				continue
			}
			if r.AttemptCount >= r.DeliveryPolicy.MaxAttempts {
				continue
			}
			if r.LastAttemptAt != nil {
				last, parseErr := parseTime(*r.LastAttemptAt)
				if parseErr != nil || now.Before(last) {
					return ErrUnsafeRecord
				}
			}
			stamp := p.RFC3339Timestamp(now.UTC().Format(time.RFC3339Nano))
			r.State = p.ReconciliationStateSending
			r.AttemptCount++
			r.LastAttemptAt = &stamp
			r.NextAttemptAt = nil
			if err := q.writeRecord(ctx, env, r); err != nil {
				return err
			}
			result = r
			return nil
		}
		if foundBlocked {
			return ErrNotReady
		}
		return ErrNotFound
	})
	return result, err
}

func (q *unixQueue) validateBatchGroup(items []diskEnvelope) error {
	if len(items) == 0 {
		return nil
	}
	checkpoint, err := q.readCheckpoint(items[0].Record.BatchID)
	if err != nil {
		return err
	}
	first := items[0].Record.BatchSequence
	if first != 0 && first != checkpoint.ExpectedNextSequence {
		return ErrCorrupt
	}
	for index, env := range items {
		r := env.Record
		if env.TenantHash != items[0].TenantHash || env.SubjectHash != items[0].SubjectHash {
			return ErrCorrupt
		}
		if index > 0 && r.BatchSequence != items[index-1].Record.BatchSequence+1 {
			return ErrCorrupt
		}
		if r.BatchSequence < checkpoint.ExpectedNextSequence {
			entry, ok := checkpoint.CompletedPrefix[strconv.FormatInt(int64(r.BatchSequence), 10)]
			if !ok || r.State != p.ReconciliationStateAcknowledged ||
				entry.ReconciliationID != r.ReconciliationID || entry.EvidenceHash != env.EvidenceHash {
				return ErrCorrupt
			}
		} else if r.State == p.ReconciliationStateAcknowledged {
			return ErrCorrupt
		} else if r.State == p.ReconciliationStateDiscarded && index != len(items)-1 {
			return ErrCorrupt
		}
	}
	if first <= checkpoint.ExpectedNextSequence {
		lastPrefix := checkpoint.ExpectedNextSequence - 1
		if first <= lastPrefix &&
			(items[len(items)-1].Record.BatchSequence < lastPrefix ||
				items[int(lastPrefix-first)].Record.BatchSequence != lastPrefix) {
			return ErrCorrupt
		}
	}
	return nil
}

func (q *unixQueue) validateAllBatchGroups() error {
	names, err := q.names()
	if err != nil {
		return err
	}
	items := make([]diskEnvelope, 0, len(names))
	for _, name := range names {
		env, readErr := q.read(name)
		if readErr != nil {
			return readErr
		}
		items = append(items, env)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Record.BatchID != items[j].Record.BatchID {
			return items[i].Record.BatchID < items[j].Record.BatchID
		}
		if items[i].Record.BatchSequence != items[j].Record.BatchSequence {
			return items[i].Record.BatchSequence < items[j].Record.BatchSequence
		}
		return items[i].Record.ReconciliationID < items[j].Record.ReconciliationID
	})
	for start := 0; start < len(items); {
		end := start + 1
		for end < len(items) && items[end].Record.BatchID == items[start].Record.BatchID {
			end++
		}
		if err := q.validateBatchGroup(items[start:end]); err != nil {
			return err
		}
		start = end
	}
	return nil
}

func (q *unixQueue) recover(ctx context.Context, b Binding, now time.Time) (p.ReconciliationRecord, error) {
	if !validBinding(b) || now.IsZero() {
		return p.ReconciliationRecord{}, ErrUnsafeRecord
	}
	var result p.ReconciliationRecord
	err := q.withLock(ctx, func() error {
		items, err := q.boundRecords(b)
		if err != nil {
			return err
		}
		for _, env := range items {
			r := env.Record
			if r.State != p.ReconciliationStateSending {
				continue
			}
			if r.LastAttemptAt == nil || now.Before(timeMust(r.LastAttemptAt)) {
				return ErrUnsafeRecord
			}
			r.State = p.ReconciliationStatePending
			if r.AttemptCount >= r.DeliveryPolicy.MaxAttempts {
				reason := "attempt_limit_reached"
				r.DeliveryDisposition = p.DeliveryDispositionManualIntervention
				r.ManualReasonCode = &reason
			}
			if err := q.writeRecord(ctx, env, r); err != nil {
				return err
			}
			result = r
			return nil
		}
		return ErrNotFound
	})
	return result, err
}

func (q *unixQueue) recoverAllSending(ctx context.Context) error {
	names, err := q.names()
	if err != nil {
		return err
	}
	for _, name := range names {
		env, readErr := q.read(name)
		if readErr != nil {
			return readErr
		}
		r := env.Record
		if r.State != p.ReconciliationStateSending {
			continue
		}
		r.State = p.ReconciliationStatePending
		if r.DeliveryDisposition == p.DeliveryDispositionManualIntervention ||
			r.AttemptCount >= r.DeliveryPolicy.MaxAttempts {
			reason := "attempt_limit_reached"
			r.DeliveryDisposition = p.DeliveryDispositionManualIntervention
			r.ManualReasonCode = &reason
		}
		if err := q.writeRecord(ctx, env, r); err != nil {
			return err
		}
	}
	return nil
}

func (q *unixQueue) fail(ctx context.Context, b Binding, id p.ReconciliationID, now time.Time, retryable bool, minimumDelay time.Duration) (p.ReconciliationRecord, error) {
	if !retryable {
		if err := q.hold(ctx, b, id, DeliveryRejected); err != nil {
			return p.ReconciliationRecord{}, err
		}
		return q.get(ctx, b, id)
	}
	var result p.ReconciliationRecord
	err := q.transition(ctx, b, id, func(env diskEnvelope) (p.ReconciliationRecord, error) {
		r := env.Record
		if r.State != p.ReconciliationStateSending {
			return r, ErrConflict
		}
		last := timeMust(r.LastAttemptAt)
		if now.IsZero() || now.Before(last) {
			return r, ErrUnsafeRecord
		}
		if r.AttemptCount >= r.DeliveryPolicy.MaxAttempts {
			r.State = p.ReconciliationStatePending
			reason := "attempt_limit_reached"
			r.DeliveryDisposition = p.DeliveryDispositionManualIntervention
			r.ManualReasonCode = &reason
		} else {
			delay, err := retryDelay(r, q.config.Jitter)
			if err != nil {
				return r, err
			}
			maximum := time.Duration(r.DeliveryPolicy.MaxDelaySeconds) * time.Second
			if minimumDelay > maximum {
				minimumDelay = maximum
			}
			if minimumDelay > delay {
				delay = minimumDelay
			}
			next := p.RFC3339Timestamp(now.UTC().Add(delay).Format(time.RFC3339Nano))
			r.State = p.ReconciliationStateRetryWait
			r.NextAttemptAt = &next
		}
		result = r
		return r, nil
	})
	return result, err
}

func (q *unixQueue) ack(ctx context.Context, b Binding, id p.ReconciliationID, receipt VerifiedReceipt) (p.ReconciliationRecord, error) {
	var result p.ReconciliationRecord
	err := q.withLock(ctx, func() error {
		if receipt.seal != hardenedReceiptSeal {
			return ErrRejected
		}
		env, err := q.read(recordName(id))
		if err != nil {
			return err
		}
		if env.TenantHash != hashBinding(b, true) || env.SubjectHash != hashBinding(b, false) {
			return ErrNotFound
		}
		r := env.Record
		if r.State == p.ReconciliationStateAcknowledged {
			if r.Acknowledgement != nil &&
				*r.Acknowledgement == receipt.ack &&
				receipt.tenant == b.Tenant && receipt.clientID == r.ClientID &&
				!receipt.verifiedAt.IsZero() && !timeMust(&receipt.ack.AcknowledgedAt).After(receipt.verifiedAt) {
				result = r
				return q.ensureCheckpointEntry(ctx, env)
			}
			return ErrConflict
		}
		if r.State != p.ReconciliationStateSending || receipt.tenant != b.Tenant || receipt.clientID != r.ClientID ||
			receipt.ack.ReconciliationID != r.ReconciliationID || receipt.ack.EvidenceHash != env.EvidenceHash {
			return ErrRejected
		}
		at, err := parseTime(receipt.ack.AcknowledgedAt)
		if err != nil || receipt.verifiedAt.IsZero() || at.After(receipt.verifiedAt) ||
			at.Before(timeMust(r.LastAttemptAt)) {
			return ErrRejected
		}
		r.State = p.ReconciliationStateAcknowledged
		r.AcknowledgedAt = &receipt.ack.AcknowledgedAt
		ack := receipt.ack
		r.Acknowledgement = &ack
		result = r
		if _, err := validateRecord(r, q.config.MaxRecordBytes); err != nil {
			return err
		}
		checkpoint, err := q.readCheckpoint(r.BatchID)
		if err != nil {
			return err
		}
		if r.BatchSequence != checkpoint.ExpectedNextSequence {
			return ErrConflict
		}
		key := strconv.FormatInt(int64(r.BatchSequence), 10)
		checkpoint.CompletedPrefix[key] = checkpointEntry{ReconciliationID: r.ReconciliationID, EvidenceHash: env.EvidenceHash}
		checkpoint.ExpectedNextSequence++
		env.Record = r
		return q.commitBatchTransaction(ctx, env, checkpoint)
	})
	return result, err
}

func (q *unixQueue) ensureCheckpointEntry(ctx context.Context, env diskEnvelope) error {
	checkpoint, err := q.readCheckpoint(env.Record.BatchID)
	if err != nil {
		return err
	}
	key := strconv.FormatInt(int64(env.Record.BatchSequence), 10)
	entry := checkpointEntry{ReconciliationID: env.Record.ReconciliationID, EvidenceHash: env.EvidenceHash}
	if env.Record.BatchSequence < checkpoint.ExpectedNextSequence {
		if checkpoint.CompletedPrefix[key] != entry {
			return ErrConflict
		}
		return nil
	}
	if env.Record.BatchSequence != checkpoint.ExpectedNextSequence {
		return ErrConflict
	}
	previous := checkpoint
	checkpoint.CompletedPrefix[key] = entry
	checkpoint.ExpectedNextSequence++
	return q.writeCheckpoint(ctx, checkpoint, &previous)
}

func (q *unixQueue) discard(ctx context.Context, b Binding, id p.ReconciliationID, now time.Time, authority p.DiscardAuthorityType, reason string, _ bool) (p.ReconciliationRecord, error) {
	if q.config.Authority == nil || q.config.Authority.AuthorizeDiscard(ctx, b, authority) != nil {
		return p.ReconciliationRecord{}, ErrUnauthorized
	}
	var result p.ReconciliationRecord
	err := q.transition(ctx, b, id, func(env diskEnvelope) (p.ReconciliationRecord, error) {
		r := env.Record
		if r.State != p.ReconciliationStatePending ||
			!safeReason.MatchString(reason) ||
			(authority != p.DiscardAuthorityTypeAuthenticatedUser && authority != p.DiscardAuthorityTypeOrganizationRetentionPolicy) {
			return r, ErrRejected
		}
		names, listErr := q.names()
		if listErr != nil {
			return r, listErr
		}
		for _, name := range names {
			other, readErr := q.read(name)
			if readErr != nil {
				return r, readErr
			}
			if other.Record.BatchID == r.BatchID && other.Record.BatchSequence > r.BatchSequence {
				return r, ErrConflict
			}
		}
		if now.IsZero() || now.Before(timeMust(&r.ObservedAt)) ||
			(r.LastAttemptAt != nil && now.Before(timeMust(r.LastAttemptAt))) {
			return r, ErrRejected
		}
		at := p.RFC3339Timestamp(now.UTC().Format(time.RFC3339Nano))
		r.State = p.ReconciliationStateDiscarded
		r.DiscardedAt = &at
		r.NextAttemptAt = nil
		r.Discard = &p.ReconciliationDiscard{AuthorityType: authority, ReasonCode: reason}
		result = r
		return r, nil
	})
	return result, err
}

func (q *unixQueue) manualRetry(ctx context.Context, b Binding, id p.ReconciliationID, now time.Time) (p.ReconciliationRecord, error) {
	if q.config.Authority == nil || q.config.Authority.AuthorizeManualRetry(ctx, b) != nil {
		return p.ReconciliationRecord{}, ErrUnauthorized
	}
	var result p.ReconciliationRecord
	err := q.withLock(ctx, func() error {
		env, err := q.read(recordName(id))
		if err != nil {
			return err
		}
		if env.TenantHash != hashBinding(b, true) || env.SubjectHash != hashBinding(b, false) {
			return ErrNotFound
		}
		r := env.Record
		if r.State != p.ReconciliationStatePending ||
			(r.DeliveryDisposition != p.DeliveryDispositionManualIntervention && env.HoldClass == "") {
			return ErrRejected
		}
		if r.AttemptCount >= r.DeliveryPolicy.MaxTotalAttempts {
			return ErrAttemptLimit
		}
		if now.IsZero() || (r.LastAttemptAt != nil && now.Before(timeMust(r.LastAttemptAt))) {
			return ErrUnsafeRecord
		}
		stamp := p.RFC3339Timestamp(now.UTC().Format(time.RFC3339Nano))
		r.State = p.ReconciliationStateSending
		r.AttemptCount++
		r.LastAttemptAt = &stamp
		r.NextAttemptAt = nil
		env.HoldClass = ""
		result = r
		return q.writeRecord(ctx, env, r)
	})
	return result, err
}

func (q *unixQueue) hold(ctx context.Context, b Binding, id p.ReconciliationID, class DeliveryErrorClass) error {
	if class != DeliveryRejected && class != DeliveryConflict && class != DeliveryAuthentication {
		return ErrUnsafeRecord
	}
	return q.withLock(ctx, func() error {
		env, err := q.read(recordName(id))
		if err != nil {
			return err
		}
		if env.TenantHash != hashBinding(b, true) || env.SubjectHash != hashBinding(b, false) {
			return ErrNotFound
		}
		if env.Record.State != p.ReconciliationStateSending {
			return ErrConflict
		}
		env.Record.State = p.ReconciliationStatePending
		if env.Record.AttemptCount >= env.Record.DeliveryPolicy.MaxAttempts {
			reason := "attempt_limit_reached"
			env.Record.DeliveryDisposition = p.DeliveryDispositionManualIntervention
			env.Record.ManualReasonCode = &reason
		}
		env.HoldClass = class
		return q.writeRecord(ctx, env, env.Record)
	})
}

func (q *unixQueue) held(ctx context.Context, b Binding, id p.ReconciliationID) (DeliveryErrorClass, error) {
	if !validBinding(b) {
		return "", ErrUnsafeRecord
	}
	var class DeliveryErrorClass
	err := q.withLock(ctx, func() error {
		env, err := q.read(recordName(id))
		if err != nil {
			return err
		}
		if env.TenantHash != hashBinding(b, true) || env.SubjectHash != hashBinding(b, false) {
			return ErrNotFound
		}
		class = env.HoldClass
		if class == "" {
			return ErrNotFound
		}
		return nil
	})
	return class, err
}

func (q *unixQueue) transition(ctx context.Context, b Binding, id p.ReconciliationID, fn func(diskEnvelope) (p.ReconciliationRecord, error)) error {
	if !validBinding(b) {
		return ErrUnsafeRecord
	}
	return q.withLock(ctx, func() error {
		env, err := q.read(recordName(id))
		if err != nil {
			return err
		}
		if env.TenantHash != hashBinding(b, true) || env.SubjectHash != hashBinding(b, false) {
			return ErrNotFound
		}
		next, err := fn(env)
		if err != nil {
			return err
		}
		return q.writeRecord(ctx, env, next)
	})
}

func (q *unixQueue) writeRecord(ctx context.Context, env diskEnvelope, record p.ReconciliationRecord) error {
	if _, err := validateRecord(record, q.config.MaxRecordBytes); err != nil {
		return err
	}
	hash, err := evidenceHash(record)
	if err != nil || hash != env.EvidenceHash {
		return ErrConflict
	}
	env.Record = record
	wire, err := json.Marshal(env)
	if err != nil || len(wire) > q.config.MaxRecordBytes {
		return ErrUnsafeRecord
	}
	return q.atomicWrite(ctx, recordName(record.ReconciliationID), wire, &env)
}

func (q *unixQueue) boundRecords(b Binding) ([]diskEnvelope, error) {
	names, err := q.names()
	if err != nil {
		return nil, err
	}
	result := make([]diskEnvelope, 0, len(names))
	for _, name := range names {
		env, err := q.read(name)
		if err != nil {
			return nil, err
		}
		if env.TenantHash == hashBinding(b, true) && env.SubjectHash == hashBinding(b, false) {
			result = append(result, env)
		}
	}
	return result, nil
}

func (q *unixQueue) names() ([]string, error) {
	names, err := q.entries()
	if err != nil {
		return nil, err
	}
	var records []string
	for _, name := range names {
		if name == ".queue.lock" || isTempName(name) || isQuarantineName(name) || isCheckpointName(name) ||
			isTransactionName(name) || isDoneTransactionName(name) {
			continue
		}
		if !isRecordName(name) {
			return nil, ErrCorrupt
		}
		records = append(records, name)
		if len(records) > q.config.MaxRecords {
			return nil, ErrQueueFull
		}
	}
	return records, nil
}

func (q *unixQueue) entries() ([]string, error) {
	dup, err := unix.Dup(q.rootFD)
	if err != nil {
		return nil, ErrUnsafePath
	}
	if _, err := unix.Seek(dup, 0, 0); err != nil {
		unix.Close(dup)
		return nil, ErrUnsafePath
	}
	file := os.NewFile(uintptr(dup), "queue")
	defer file.Close()
	// One record, one checkpoint in the worst case, and at most two retained
	// operation tombstones (enqueue and acknowledgement) per record.
	limit := q.config.MaxRecords*4 + 67
	names, err := file.Readdirnames(limit)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, ErrUnsafePath
	}
	if len(names) == limit {
		return nil, ErrQueueFull
	}
	return names, nil
}
func (q *unixQueue) usage() (int, int64, error) {
	entries, err := q.entries()
	if err != nil {
		return 0, 0, err
	}
	var total int64
	count := 0
	for _, n := range entries {
		if n == ".queue.lock" || isTempName(n) {
			continue
		}
		if !isRecordName(n) && !isQuarantineName(n) && !isCheckpointName(n) &&
			!isTransactionName(n) && !isDoneTransactionName(n) {
			return 0, 0, ErrCorrupt
		}
		var st unix.Stat_t
		if unix.Fstatat(q.rootFD, n, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
			return 0, 0, ErrUnsafePath
		}
		total += st.Size
		if isRecordName(n) || isDoneTransactionName(n) {
			count++
		}
	}
	return count, total, nil
}
func (q *unixQueue) validateAll() error {
	entries, err := q.entries()
	if err != nil {
		return err
	}
	quarantined := 0
	for _, n := range entries {
		if n == ".queue.lock" {
			continue
		}
		if isTempName(n) {
			if err := q.removeStaleTemp(n); err != nil {
				return err
			}
			continue
		}
		if isQuarantineName(n) {
			quarantined++
			if quarantined > 32 {
				return ErrQueueFull
			}
			var st unix.Stat_t
			if unix.Fstatat(q.rootFD, n, &st, unix.AT_SYMLINK_NOFOLLOW) != nil ||
				st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || int(st.Uid) != os.Geteuid() || st.Mode&0o777 != 0o600 {
				return ErrUnsafePath
			}
			continue
		}
		if isTransactionName(n) {
			return ErrCorrupt
		}
		if isDoneTransactionName(n) {
			continue
		}
		if isCheckpointName(n) {
			if _, err := q.readCheckpointByName(n); err != nil {
				if errors.Is(err, ErrCorrupt) {
					_ = q.quarantine(n)
				}
				return err
			}
			continue
		}
		if !isRecordName(n) {
			return ErrCorrupt
		}
		if _, err = q.read(n); err != nil {
			if errors.Is(err, ErrCorrupt) {
				_ = q.quarantine(n)
			}
			return err
		}
	}
	_, used, err := q.usage()
	if err != nil {
		return err
	}
	if used > q.config.MaxBytes {
		return ErrQueueFull
	}
	return nil
}

func (q *unixQueue) removeStaleTemp(name string) error {
	var st unix.Stat_t
	if unix.Fstatat(q.rootFD, name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || int(st.Uid) != os.Geteuid() || st.Mode&0o777 != 0o600 {
		return ErrUnsafePath
	}
	if unix.Unlinkat(q.rootFD, name, 0) != nil || unix.Fsync(q.rootFD) != nil {
		return ErrUnsafePath
	}
	return nil
}

func (q *unixQueue) quarantine(name string) error {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return ErrUnsafePath
	}
	sum := sha256.Sum256([]byte(name))
	target := ".quarantine-" + hex.EncodeToString(sum[:]) + "-" + hex.EncodeToString(token[:])
	if unix.Renameat(q.rootFD, name, q.rootFD, target) != nil || unix.Fsync(q.rootFD) != nil {
		return ErrUnsafePath
	}
	return nil
}

func (q *unixQueue) read(name string) (diskEnvelope, error) {
	var before unix.Stat_t
	if err := unix.Fstatat(q.rootFD, name, &before, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return diskEnvelope{}, ErrNotFound
	} else if err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 {
		return diskEnvelope{}, ErrUnsafePath
	}
	fd, err := unix.Openat(q.rootFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return diskEnvelope{}, ErrNotFound
	}
	if err != nil {
		return diskEnvelope{}, ErrUnsafePath
	}
	defer unix.Close(fd)
	if err = validateRegular(fd, 0o600); err != nil {
		return diskEnvelope{}, err
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || uint64(st.Dev) != uint64(before.Dev) || uint64(st.Ino) != uint64(before.Ino) ||
		st.Size <= 0 || st.Size > int64(q.config.MaxRecordBytes) {
		return diskEnvelope{}, ErrCorrupt
	}
	document := make([]byte, int(st.Size))
	offset := 0
	for offset < len(document) {
		n, readErr := unix.Read(fd, document[offset:])
		if readErr != nil || n == 0 {
			return diskEnvelope{}, ErrCorrupt
		}
		offset += n
	}
	var env diskEnvelope
	dec := json.NewDecoder(bytes.NewReader(document))
	dec.DisallowUnknownFields()
	if dec.Decode(&env) != nil || dec.Decode(&struct{}{}) != io.EOF || env.Version != envelopeVersion {
		return diskEnvelope{}, ErrCorrupt
	}
	if recordName(env.Record.ReconciliationID) != name {
		return diskEnvelope{}, ErrCorrupt
	}
	if _, err = validateRecord(env.Record, q.config.MaxRecordBytes); err != nil {
		return diskEnvelope{}, ErrCorrupt
	}
	hash, e := evidenceHash(env.Record)
	if e != nil || hash != env.EvidenceHash {
		return diskEnvelope{}, ErrCorrupt
	}
	if len(env.TenantHash) != 64 || len(env.SubjectHash) != 64 {
		return diskEnvelope{}, ErrCorrupt
	}
	if env.HoldClass != "" && env.HoldClass != DeliveryRejected && env.HoldClass != DeliveryConflict &&
		env.HoldClass != DeliveryAuthentication {
		return diskEnvelope{}, ErrCorrupt
	}
	env.dev, env.ino = uint64(st.Dev), uint64(st.Ino)
	env.digest = sha256.Sum256(document)
	return env, nil
}

func (q *unixQueue) readCheckpoint(batchID p.BatchID) (batchCheckpoint, error) {
	return q.readCheckpointByName(checkpointName(batchID))
}

func (q *unixQueue) readCheckpointByName(name string) (batchCheckpoint, error) {
	var before unix.Stat_t
	if err := unix.Fstatat(q.rootFD, name, &before, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return batchCheckpoint{}, ErrNotFound
	} else if err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 {
		return batchCheckpoint{}, ErrUnsafePath
	}
	fd, err := unix.Openat(q.rootFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return batchCheckpoint{}, ErrUnsafePath
	}
	defer unix.Close(fd)
	if err := validateRegular(fd, 0o600); err != nil {
		return batchCheckpoint{}, err
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Dev != before.Dev || st.Ino != before.Ino ||
		st.Size <= 0 || st.Size > int64(q.config.MaxRecordBytes) {
		return batchCheckpoint{}, ErrCorrupt
	}
	document := make([]byte, int(st.Size))
	for offset := 0; offset < len(document); {
		n, readErr := unix.Read(fd, document[offset:])
		if readErr != nil || n == 0 {
			return batchCheckpoint{}, ErrCorrupt
		}
		offset += n
	}
	var checkpoint batchCheckpoint
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&checkpoint) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		checkpoint.Version != envelopeVersion || checkpointName(checkpoint.BatchID) != name ||
		checkpoint.ExpectedNextSequence < 0 || checkpoint.ExpectedNextSequence > p.JSONInteger(q.config.MaxRecords) ||
		len(checkpoint.CompletedPrefix) != int(checkpoint.ExpectedNextSequence) {
		return batchCheckpoint{}, ErrCorrupt
	}
	for sequence := p.JSONInteger(0); sequence < checkpoint.ExpectedNextSequence; sequence++ {
		entry, ok := checkpoint.CompletedPrefix[strconv.FormatInt(int64(sequence), 10)]
		if !ok || entry.ReconciliationID == "" || entry.EvidenceHash == "" {
			return batchCheckpoint{}, ErrCorrupt
		}
	}
	checkpoint.dev, checkpoint.ino = uint64(st.Dev), uint64(st.Ino)
	checkpoint.digest = sha256.Sum256(document)
	return checkpoint, nil
}

func (q *unixQueue) writeCheckpoint(ctx context.Context, checkpoint batchCheckpoint, previous *batchCheckpoint) error {
	wire, err := json.Marshal(checkpoint)
	if err != nil || len(wire) > q.config.MaxRecordBytes {
		return ErrQueueFull
	}
	var expected *diskEnvelope
	if previous != nil {
		expected = &diskEnvelope{dev: previous.dev, ino: previous.ino, digest: previous.digest}
	}
	return q.atomicWrite(ctx, checkpointName(checkpoint.BatchID), wire, expected)
}

func (q *unixQueue) commitBatchTransaction(ctx context.Context, env diskEnvelope, checkpoint batchCheckpoint) error {
	transaction := batchTransaction{
		Version: envelopeVersion, Operation: "ack", RecordName: recordName(env.Record.ReconciliationID),
		CheckpointName:      checkpointName(checkpoint.BatchID),
		OldRecordDigest:     hex.EncodeToString(env.digest[:]),
		OldCheckpointDigest: hex.EncodeToString(checkpoint.digest[:]),
		NewEnvelope:         env, NewCheckpoint: checkpoint,
	}
	name := transactionControlName(".txn-", transaction)
	document, err := json.Marshal(transaction)
	if err != nil || int64(len(document)) > maxTransactionBytes {
		return ErrQueueFull
	}
	if err := q.atomicWrite(ctx, name, document, nil); err != nil {
		return err
	}
	q.markRecoveryNeeded()
	persisted, snapshot, err := q.readSafeFile(name, maxTransactionBytes)
	if err != nil {
		return err
	}
	transaction, err = decodeBatchTransaction(persisted)
	if err != nil {
		return err
	}
	if err := q.applyTransaction(ctx, name, transaction, snapshot); err != nil {
		return err
	}
	q.clearRecoveryNeeded()
	return nil
}

func (q *unixQueue) commitEnqueueTransaction(ctx context.Context, transaction batchTransaction) error {
	name := transactionControlName(".txn-", transaction)
	document, err := json.Marshal(transaction)
	if err != nil || int64(len(document)) > maxTransactionBytes {
		return ErrQueueFull
	}
	if err := q.atomicWrite(ctx, name, document, nil); err != nil {
		return err
	}
	q.markRecoveryNeeded()
	persisted, snapshot, err := q.readSafeFile(name, maxTransactionBytes)
	if err != nil {
		return err
	}
	transaction, err = decodeBatchTransaction(persisted)
	if err != nil {
		return err
	}
	if err := q.applyTransaction(ctx, name, transaction, snapshot); err != nil {
		return err
	}
	q.clearRecoveryNeeded()
	return nil
}

func transactionControlName(prefix string, transaction batchTransaction) string {
	sum := sha256.Sum256([]byte(transaction.Operation + "\x00" + transaction.RecordName))
	return prefix + hex.EncodeToString(sum[:16])
}

func (q *unixQueue) markRecoveryNeeded() {
	q.mu.Lock()
	q.needsRecovery = true
	q.mu.Unlock()
}

func (q *unixQueue) clearRecoveryNeeded() {
	q.mu.Lock()
	q.needsRecovery = false
	q.mu.Unlock()
}

func decodeBatchTransaction(document []byte) (batchTransaction, error) {
	var transaction batchTransaction
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&transaction) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		transaction.Version != envelopeVersion {
		return batchTransaction{}, ErrCorrupt
	}
	return transaction, nil
}

func (q *unixQueue) recoverTransactions(ctx context.Context) error {
	entries, err := q.entries()
	if err != nil {
		return err
	}
	count := 0
	for _, name := range entries {
		if !isTransactionName(name) && !isDoneTransactionName(name) {
			continue
		}
		count++
		if count > q.config.MaxRecords*2 {
			return ErrQueueFull
		}
		document, snapshot, readErr := q.readSafeFile(name, maxTransactionBytes)
		if readErr != nil {
			if errors.Is(readErr, ErrCorrupt) {
				if quarantineErr := q.quarantine(name); quarantineErr != nil {
					return errors.Join(readErr, quarantineErr)
				}
				if isDoneTransactionName(name) {
					return ErrCorrupt
				}
				continue
			}
			return readErr
		}
		transaction, decodeErr := decodeBatchTransaction(document)
		if decodeErr != nil {
			if isDoneTransactionName(name) {
				if tombstoneErr := validateDoneTombstone(name, document); tombstoneErr == nil {
					continue
				}
			}
			if quarantineErr := q.quarantine(name); quarantineErr != nil {
				return errors.Join(ErrCorrupt, quarantineErr)
			}
			if isDoneTransactionName(name) {
				return ErrCorrupt
			}
			continue
		}
		if isDoneTransactionName(name) {
			if verifyErr := q.verifyAppliedTransaction(transaction); verifyErr != nil {
				if quarantineErr := q.quarantine(name); quarantineErr != nil {
					return errors.Join(verifyErr, quarantineErr)
				}
				return errors.Join(ErrCorrupt, verifyErr)
			}
			if name != transactionControlName(".done-", transaction) {
				return ErrCorrupt
			}
			if retainErr := q.compactRetainedTransaction(name, snapshot, transaction); retainErr != nil {
				return retainErr
			}
			continue
		}
		if err := q.applyTransaction(ctx, name, transaction, snapshot); err != nil {
			if errors.Is(err, ErrCorrupt) || errors.Is(err, ErrConflict) {
				if quarantineErr := q.quarantine(name); quarantineErr != nil {
					return errors.Join(err, quarantineErr)
				}
				continue
			}
			return err
		}
	}
	return nil
}

func validateDoneTombstone(name string, document []byte) error {
	var tombstone doneTombstone
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&tombstone) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		tombstone.Version != envelopeVersion ||
		(tombstone.Operation != "enqueue" && tombstone.Operation != "ack") ||
		!isRecordName(tombstone.RecordName) ||
		!validHex(tombstone.JournalDigest) || len(tombstone.JournalDigest) != 64 {
		return ErrCorrupt
	}
	transaction := batchTransaction{Operation: tombstone.Operation, RecordName: tombstone.RecordName}
	if name != transactionControlName(".done-", transaction) {
		return ErrCorrupt
	}
	return nil
}

func (q *unixQueue) verifyAppliedTransaction(transaction batchTransaction) error {
	if transaction.Operation != "ack" && transaction.Operation != "enqueue" {
		return ErrCorrupt
	}
	if transaction.Version != envelopeVersion || transaction.NewEnvelope.Version != envelopeVersion ||
		transaction.NewCheckpoint.Version != envelopeVersion ||
		!isRecordName(transaction.RecordName) || !isCheckpointName(transaction.CheckpointName) ||
		recordName(transaction.NewEnvelope.Record.ReconciliationID) != transaction.RecordName ||
		checkpointName(transaction.NewCheckpoint.BatchID) != transaction.CheckpointName ||
		transaction.NewEnvelope.Record.BatchID != transaction.NewCheckpoint.BatchID ||
		!validHex(transaction.NewEnvelope.TenantHash) || len(transaction.NewEnvelope.TenantHash) != 64 ||
		!validHex(transaction.NewEnvelope.SubjectHash) || len(transaction.NewEnvelope.SubjectHash) != 64 {
		return ErrCorrupt
	}
	if transaction.Operation == "ack" {
		if err := validateTransactionShape(transaction, q.config.MaxRecords, q.config.MaxRecordBytes); err != nil {
			return err
		}
		if !validHex(transaction.OldRecordDigest) || len(transaction.OldRecordDigest) != 64 ||
			!validHex(transaction.OldCheckpointDigest) || len(transaction.OldCheckpointDigest) != 64 {
			return ErrCorrupt
		}
	} else if transaction.NewEnvelope.Record.State != p.ReconciliationStatePending ||
		transaction.NewEnvelope.Record.AttemptCount != 0 ||
		transaction.NewEnvelope.HoldClass != "" ||
		transaction.NewCheckpoint.ExpectedNextSequence < 0 ||
		transaction.NewCheckpoint.ExpectedNextSequence > p.JSONInteger(q.config.MaxRecords) ||
		len(transaction.NewCheckpoint.CompletedPrefix) != int(transaction.NewCheckpoint.ExpectedNextSequence) {
		return ErrCorrupt
	}
	for sequence := p.JSONInteger(0); sequence < transaction.NewCheckpoint.ExpectedNextSequence; sequence++ {
		entry, ok := transaction.NewCheckpoint.CompletedPrefix[strconv.FormatInt(int64(sequence), 10)]
		if !ok || entry.ReconciliationID == "" || entry.EvidenceHash == "" {
			return ErrCorrupt
		}
	}
	if _, err := validateRecord(transaction.NewEnvelope.Record, q.config.MaxRecordBytes); err != nil {
		return ErrCorrupt
	}
	hash, err := evidenceHash(transaction.NewEnvelope.Record)
	if err != nil || hash != transaction.NewEnvelope.EvidenceHash {
		return ErrCorrupt
	}
	recordWire, err := json.Marshal(transaction.NewEnvelope)
	if err != nil || len(recordWire) > q.config.MaxRecordBytes {
		return ErrCorrupt
	}
	record, err := q.read(transaction.RecordName)
	if err != nil || record.digest != sha256.Sum256(recordWire) {
		return ErrConflict
	}
	checkpointWire, err := json.Marshal(transaction.NewCheckpoint)
	if err != nil || len(checkpointWire) > q.config.MaxRecordBytes {
		return ErrCorrupt
	}
	checkpoint, err := q.readCheckpointByName(transaction.CheckpointName)
	if err != nil || checkpoint.digest != sha256.Sum256(checkpointWire) {
		return ErrConflict
	}
	return nil
}

func (q *unixQueue) applyTransaction(ctx context.Context, name string, transaction batchTransaction, transactionSnapshot fileSnapshot) error {
	if transaction.Operation == "enqueue" {
		return q.applyEnqueueTransaction(ctx, name, transaction, transactionSnapshot)
	}
	if err := validateTransactionShape(transaction, q.config.MaxRecords, q.config.MaxRecordBytes); err != nil {
		return err
	}
	if !isRecordName(transaction.RecordName) || !isCheckpointName(transaction.CheckpointName) ||
		recordName(transaction.NewEnvelope.Record.ReconciliationID) != transaction.RecordName ||
		checkpointName(transaction.NewCheckpoint.BatchID) != transaction.CheckpointName ||
		!validHex(transaction.OldRecordDigest) || len(transaction.OldRecordDigest) != 64 ||
		!validHex(transaction.OldCheckpointDigest) || len(transaction.OldCheckpointDigest) != 64 ||
		transaction.NewEnvelope.Record.BatchID != transaction.NewCheckpoint.BatchID ||
		!validHex(transaction.NewEnvelope.TenantHash) || len(transaction.NewEnvelope.TenantHash) != 64 ||
		!validHex(transaction.NewEnvelope.SubjectHash) || len(transaction.NewEnvelope.SubjectHash) != 64 ||
		(transaction.NewEnvelope.HoldClass != "" && transaction.NewEnvelope.HoldClass != DeliveryRejected &&
			transaction.NewEnvelope.HoldClass != DeliveryConflict && transaction.NewEnvelope.HoldClass != DeliveryAuthentication) {
		return ErrCorrupt
	}
	if _, err := validateRecord(transaction.NewEnvelope.Record, q.config.MaxRecordBytes); err != nil {
		return ErrCorrupt
	}
	hash, err := evidenceHash(transaction.NewEnvelope.Record)
	if err != nil || hash != transaction.NewEnvelope.EvidenceHash {
		return ErrCorrupt
	}
	recordWire, err := json.Marshal(transaction.NewEnvelope)
	if err != nil {
		return ErrCorrupt
	}
	checkpointWire, err := json.Marshal(transaction.NewCheckpoint)
	if err != nil {
		return ErrCorrupt
	}
	current, err := q.read(transaction.RecordName)
	newRecordDigest := sha256.Sum256(recordWire)
	if err != nil {
		return err
	}
	if current.EvidenceHash != transaction.NewEnvelope.EvidenceHash ||
		current.TenantHash != transaction.NewEnvelope.TenantHash || current.SubjectHash != transaction.NewEnvelope.SubjectHash ||
		current.Record.AttemptCount != transaction.NewEnvelope.Record.AttemptCount ||
		current.Record.LastAttemptAt == nil || transaction.NewEnvelope.Record.LastAttemptAt == nil ||
		*current.Record.LastAttemptAt != *transaction.NewEnvelope.Record.LastAttemptAt ||
		transaction.NewEnvelope.Record.State != p.ReconciliationStateAcknowledged ||
		(current.Record.State != p.ReconciliationStateSending && current.digest != newRecordDigest) {
		return ErrCorrupt
	}
	if current.digest != newRecordDigest {
		if hex.EncodeToString(current.digest[:]) != transaction.OldRecordDigest {
			return ErrConflict
		}
		if err := q.atomicWrite(ctx, transaction.RecordName, recordWire, &current); err != nil {
			return err
		}
	}
	if q.afterTransactionRecord != nil {
		if err := q.afterTransactionRecord(); err != nil {
			return err
		}
	}
	currentCheckpoint, err := q.readCheckpointByName(transaction.CheckpointName)
	newCheckpointDigest := sha256.Sum256(checkpointWire)
	if err != nil {
		return err
	}
	if currentCheckpoint.digest != newCheckpointDigest {
		if transaction.NewCheckpoint.ExpectedNextSequence != currentCheckpoint.ExpectedNextSequence+1 ||
			len(transaction.NewCheckpoint.CompletedPrefix) != len(currentCheckpoint.CompletedPrefix)+1 {
			return ErrCorrupt
		}
		for key, value := range currentCheckpoint.CompletedPrefix {
			if transaction.NewCheckpoint.CompletedPrefix[key] != value {
				return ErrCorrupt
			}
		}
		key := strconv.FormatInt(int64(current.Record.BatchSequence), 10)
		expected := checkpointEntry{ReconciliationID: current.Record.ReconciliationID, EvidenceHash: current.EvidenceHash}
		if transaction.NewCheckpoint.CompletedPrefix[key] != expected {
			return ErrCorrupt
		}
	}
	if currentCheckpoint.digest != newCheckpointDigest {
		if hex.EncodeToString(currentCheckpoint.digest[:]) != transaction.OldCheckpointDigest {
			return ErrConflict
		}
		expected := diskEnvelope{dev: currentCheckpoint.dev, ino: currentCheckpoint.ino, digest: currentCheckpoint.digest}
		if err := q.atomicWrite(ctx, transaction.CheckpointName, checkpointWire, &expected); err != nil {
			return err
		}
	}
	return q.finishTransaction(name, transactionSnapshot, transaction)
}

func (q *unixQueue) applyEnqueueTransaction(ctx context.Context, name string, transaction batchTransaction, snapshot fileSnapshot) error {
	if transaction.Operation != "enqueue" || transaction.Version != envelopeVersion ||
		transaction.NewEnvelope.Version != envelopeVersion || transaction.NewEnvelope.Record.State != p.ReconciliationStatePending ||
		transaction.NewEnvelope.Record.AttemptCount != 0 || !isRecordName(transaction.RecordName) ||
		!isCheckpointName(transaction.CheckpointName) ||
		recordName(transaction.NewEnvelope.Record.ReconciliationID) != transaction.RecordName ||
		checkpointName(transaction.NewCheckpoint.BatchID) != transaction.CheckpointName ||
		transaction.NewEnvelope.Record.BatchID != transaction.NewCheckpoint.BatchID ||
		transaction.NewCheckpoint.Version != envelopeVersion ||
		!validHex(transaction.NewEnvelope.TenantHash) || len(transaction.NewEnvelope.TenantHash) != 64 ||
		!validHex(transaction.NewEnvelope.SubjectHash) || len(transaction.NewEnvelope.SubjectHash) != 64 ||
		transaction.NewEnvelope.HoldClass != "" ||
		transaction.NewCheckpoint.ExpectedNextSequence < 0 ||
		transaction.NewCheckpoint.ExpectedNextSequence > p.JSONInteger(q.config.MaxRecords) ||
		len(transaction.NewCheckpoint.CompletedPrefix) != int(transaction.NewCheckpoint.ExpectedNextSequence) {
		return ErrCorrupt
	}
	for sequence := p.JSONInteger(0); sequence < transaction.NewCheckpoint.ExpectedNextSequence; sequence++ {
		entry, ok := transaction.NewCheckpoint.CompletedPrefix[strconv.FormatInt(int64(sequence), 10)]
		if !ok || entry.ReconciliationID == "" || entry.EvidenceHash == "" {
			return ErrCorrupt
		}
	}
	if _, err := validateRecord(transaction.NewEnvelope.Record, q.config.MaxRecordBytes); err != nil {
		return ErrCorrupt
	}
	hash, err := evidenceHash(transaction.NewEnvelope.Record)
	if err != nil || hash != transaction.NewEnvelope.EvidenceHash {
		return ErrCorrupt
	}
	if err := q.validateEnqueueTransactionAuthority(transaction); err != nil {
		return err
	}
	checkpointWire, err := json.Marshal(transaction.NewCheckpoint)
	if err != nil || len(checkpointWire) > q.config.MaxRecordBytes {
		return ErrCorrupt
	}
	checkpoint, err := q.readCheckpointByName(transaction.CheckpointName)
	if errors.Is(err, ErrNotFound) {
		if transaction.OldCheckpointDigest != "" || transaction.NewCheckpoint.ExpectedNextSequence != 0 ||
			len(transaction.NewCheckpoint.CompletedPrefix) != 0 {
			return ErrCorrupt
		}
		if err := q.atomicWrite(ctx, transaction.CheckpointName, checkpointWire, nil); err != nil {
			return err
		}
		if q.afterCheckpointCreate != nil {
			if fault := q.afterCheckpointCreate(); fault != nil {
				return fault
			}
		}
	} else if err != nil {
		return err
	} else if sha256.Sum256(checkpointWire) != checkpoint.digest ||
		(transaction.OldCheckpointDigest != "" && transaction.OldCheckpointDigest != hex.EncodeToString(checkpoint.digest[:])) {
		return ErrConflict
	}
	recordWire, err := json.Marshal(transaction.NewEnvelope)
	if err != nil || len(recordWire) > q.config.MaxRecordBytes {
		return ErrCorrupt
	}
	current, err := q.read(transaction.RecordName)
	if errors.Is(err, ErrNotFound) {
		if err := q.atomicWrite(ctx, transaction.RecordName, recordWire, nil); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if current.digest != sha256.Sum256(recordWire) {
		return ErrConflict
	}
	return q.finishTransaction(name, snapshot, transaction)
}

// validateEnqueueTransactionAuthority fences a syntactically valid journal
// against the current authoritative batch state before either target is
// written. A crafted journal cannot create a gap, cross an ownership
// partition, or reuse a sequence for different evidence.
func (q *unixQueue) validateEnqueueTransactionAuthority(transaction batchTransaction) error {
	candidate := transaction.NewEnvelope
	candidateWire, err := json.Marshal(candidate)
	if err != nil {
		return ErrCorrupt
	}
	candidateDigest := sha256.Sum256(candidateWire)
	checkpoint, checkpointErr := q.readCheckpointByName(transaction.CheckpointName)
	if checkpointErr != nil && !errors.Is(checkpointErr, ErrNotFound) {
		return checkpointErr
	}
	if checkpointErr == nil {
		newCheckpointWire, marshalErr := json.Marshal(transaction.NewCheckpoint)
		if marshalErr != nil {
			return ErrCorrupt
		}
		checkpointWasCreated := transaction.OldCheckpointDigest == "" &&
			checkpoint.digest == sha256.Sum256(newCheckpointWire) &&
			checkpoint.ExpectedNextSequence == 0
		checkpointWasExisting := transaction.OldCheckpointDigest != "" &&
			transaction.OldCheckpointDigest == hex.EncodeToString(checkpoint.digest[:])
		if (!checkpointWasCreated && !checkpointWasExisting) ||
			checkpoint.BatchID != candidate.Record.BatchID ||
			checkpoint.ExpectedNextSequence != transaction.NewCheckpoint.ExpectedNextSequence ||
			len(checkpoint.CompletedPrefix) != len(transaction.NewCheckpoint.CompletedPrefix) {
			return ErrConflict
		}
		for key, entry := range checkpoint.CompletedPrefix {
			if transaction.NewCheckpoint.CompletedPrefix[key] != entry {
				return ErrConflict
			}
		}
	} else if transaction.OldCheckpointDigest != "" ||
		transaction.NewCheckpoint.ExpectedNextSequence != 0 ||
		len(transaction.NewCheckpoint.CompletedPrefix) != 0 {
		return ErrConflict
	}

	names, err := q.names()
	if err != nil {
		return err
	}
	maxSequence := p.JSONInteger(-1)
	candidateAlreadyPublished := false
	for _, recordFile := range names {
		current, readErr := q.read(recordFile)
		if readErr != nil {
			return readErr
		}
		if current.Record.BatchID != candidate.Record.BatchID {
			continue
		}
		if current.TenantHash != candidate.TenantHash || current.SubjectHash != candidate.SubjectHash {
			return ErrConflict
		}
		if current.Record.ReconciliationID == candidate.Record.ReconciliationID {
			if current.digest != candidateDigest || current.EvidenceHash != candidate.EvidenceHash {
				return ErrConflict
			}
			candidateAlreadyPublished = true
		} else if current.Record.BatchSequence == candidate.Record.BatchSequence {
			return ErrConflict
		}
		if current.Record.State == p.ReconciliationStateDiscarded {
			return ErrConflict
		}
		if current.Record.BatchSequence > maxSequence {
			maxSequence = current.Record.BatchSequence
		}
	}
	expected := p.JSONInteger(0)
	if checkpointErr == nil {
		expected = checkpoint.ExpectedNextSequence
	}
	if maxSequence >= expected {
		expected = maxSequence + 1
	}
	if candidateAlreadyPublished {
		if candidate.Record.BatchSequence >= expected {
			return ErrConflict
		}
		return nil
	}
	if candidate.Record.BatchSequence != expected {
		return ErrConflict
	}
	return nil
}

func (q *unixQueue) finishTransaction(name string, snapshot fileSnapshot, transaction batchTransaction) error {
	_, currentSnapshot, readErr := q.readSafeFile(name, maxTransactionBytes)
	if readErr != nil || currentSnapshot != snapshot {
		return ErrDurabilityIndeterminate
	}
	if q.beforeTransactionRemove != nil {
		if err := q.beforeTransactionRemove(name); err != nil {
			return err
		}
	}
	quarantined := transactionControlName(".done-", transaction)
	if err := quarantineAtomicNoReplace(q.rootFD, name, quarantined); err != nil {
		return err
	}
	if q.afterTransactionRename != nil {
		if err := q.afterTransactionRename(); err != nil {
			return err
		}
	}
	if unix.Fsync(q.rootFD) != nil {
		return ErrDurabilityIndeterminate
	}
	if q.afterTransactionDirSync != nil {
		if err := q.afterTransactionDirSync(); err != nil {
			return err
		}
	}
	_, movedSnapshot, readErr := q.readSafeFile(quarantined, maxTransactionBytes)
	if readErr != nil || movedSnapshot != snapshot {
		return ErrDurabilityIndeterminate
	}
	if q.afterTransactionVerify != nil {
		if err := q.afterTransactionVerify(); err != nil {
			return err
		}
	}
	return q.compactRetainedTransaction(quarantined, snapshot, transaction)
}

func (q *unixQueue) compactRetainedTransaction(name string, snapshot fileSnapshot, transaction batchTransaction) error {
	fd, err := unix.Openat(q.rootFD, name, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return ErrDurabilityIndeterminate
	}
	defer unix.Close(fd)
	if err := validateRegular(fd, 0o600); err != nil {
		return err
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || uint64(st.Dev) != snapshot.dev || uint64(st.Ino) != snapshot.ino {
		return ErrDurabilityIndeterminate
	}
	tombstone := doneTombstone{Version: envelopeVersion, Operation: transaction.Operation,
		RecordName: transaction.RecordName, JournalDigest: hex.EncodeToString(snapshot.digest[:])}
	document, err := json.Marshal(tombstone)
	if err != nil || int64(len(document)) > maxTransactionBytes {
		return ErrCorrupt
	}
	if unix.Ftruncate(fd, int64(len(document))) != nil {
		return ErrDurabilityIndeterminate
	}
	written := 0
	for written < len(document) {
		n, writeErr := unix.Pwrite(fd, document[written:], int64(written))
		if writeErr != nil || n == 0 {
			return ErrDurabilityIndeterminate
		}
		written += n
	}
	if unix.Fsync(fd) != nil {
		return ErrDurabilityIndeterminate
	}
	var pathStat unix.Stat_t
	if unix.Fstatat(q.rootFD, name, &pathStat, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		uint64(pathStat.Dev) != snapshot.dev || uint64(pathStat.Ino) != snapshot.ino {
		return ErrDurabilityIndeterminate
	}
	return nil
}

func validateTransactionShape(transaction batchTransaction, maxRecords, maxRecordBytes int) error {
	if transaction.Operation != "ack" || transaction.Version != envelopeVersion || maxRecords < 1 ||
		transaction.NewEnvelope.Version != envelopeVersion ||
		transaction.NewCheckpoint.Version != envelopeVersion ||
		transaction.NewCheckpoint.ExpectedNextSequence < 1 ||
		transaction.NewCheckpoint.ExpectedNextSequence > p.JSONInteger(maxRecords) ||
		len(transaction.NewCheckpoint.CompletedPrefix) != int(transaction.NewCheckpoint.ExpectedNextSequence) {
		return ErrCorrupt
	}
	for sequence := p.JSONInteger(0); sequence < transaction.NewCheckpoint.ExpectedNextSequence; sequence++ {
		entry, ok := transaction.NewCheckpoint.CompletedPrefix[strconv.FormatInt(int64(sequence), 10)]
		if !ok || entry.ReconciliationID == "" || entry.EvidenceHash == "" {
			return ErrCorrupt
		}
	}
	wire, err := json.Marshal(transaction.NewEnvelope)
	if err != nil || len(wire) > maxRecordBytes {
		return ErrCorrupt
	}
	checkpointWire, err := json.Marshal(transaction.NewCheckpoint)
	if err != nil || len(checkpointWire) > maxRecordBytes {
		return ErrCorrupt
	}
	return nil
}

func (q *unixQueue) readSafeFile(name string, maximum int64) ([]byte, fileSnapshot, error) {
	fd, err := unix.Openat(q.rootFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fileSnapshot{}, ErrUnsafePath
	}
	defer unix.Close(fd)
	if err := validateRegular(fd, 0o600); err != nil {
		return nil, fileSnapshot{}, err
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Size <= 0 || st.Size > maximum {
		return nil, fileSnapshot{}, ErrCorrupt
	}
	document := make([]byte, int(st.Size))
	for offset := 0; offset < len(document); {
		n, readErr := unix.Read(fd, document[offset:])
		if readErr != nil || n == 0 {
			return nil, fileSnapshot{}, ErrCorrupt
		}
		offset += n
	}
	return document, fileSnapshot{dev: uint64(st.Dev), ino: uint64(st.Ino), digest: sha256.Sum256(document)}, nil
}

func (q *unixQueue) atomicWrite(ctx context.Context, name string, document []byte, expected *diskEnvelope) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	_, used, usageErr := q.usage()
	if usageErr != nil {
		return usageErr
	}
	if int64(len(document)) > q.config.MaxBytes || used > q.config.MaxBytes-int64(len(document)) {
		return ErrQueueFull
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return ErrUnsafePath
	}
	tmp := ".tmp-" + hex.EncodeToString(token[:])
	fd, err := unix.Openat(q.rootFD, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return ErrUnsafePath
	}
	keep := false
	defer func() {
		unix.Close(fd)
		if !keep {
			unix.Unlinkat(q.rootFD, tmp, 0)
		}
	}()
	if err = validateRegular(fd, 0o600); err != nil {
		return err
	}
	var tempIdentity unix.Stat_t
	if unix.Fstat(fd, &tempIdentity) != nil {
		return ErrUnsafePath
	}
	written := 0
	for written < len(document) {
		n, e := unix.Write(fd, document[written:])
		written += n
		if e != nil || n == 0 {
			return ErrUnsafePath
		}
	}
	if unix.Fsync(fd) != nil {
		return ErrUnsafePath
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	var current unix.Stat_t
	statErr := unix.Fstatat(q.rootFD, name, &current, unix.AT_SYMLINK_NOFOLLOW)
	if expected == nil {
		if statErr == nil {
			return ErrConflict
		}
		if !errors.Is(statErr, unix.ENOENT) {
			return ErrUnsafePath
		}
	} else if statErr != nil || uint64(current.Dev) != expected.dev || uint64(current.Ino) != expected.ino ||
		current.Mode&unix.S_IFMT != unix.S_IFREG || current.Nlink != 1 {
		return ErrConflict
	}
	var tempPathIdentity unix.Stat_t
	if unix.Fstatat(q.rootFD, tmp, &tempPathIdentity, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		tempPathIdentity.Dev != tempIdentity.Dev || tempPathIdentity.Ino != tempIdentity.Ino ||
		tempPathIdentity.Mode&unix.S_IFMT != unix.S_IFREG || tempPathIdentity.Nlink != 1 {
		return ErrConflict
	}
	if err := publishAtomic(q.rootFD, tmp, name, expected); err != nil {
		return err
	}
	keep = true
	var published unix.Stat_t
	if unix.Fstatat(q.rootFD, name, &published, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		published.Dev != tempIdentity.Dev || published.Ino != tempIdentity.Ino {
		return ErrConflict
	}
	if unix.Fsync(q.rootFD) != nil {
		return ErrUnsafePath
	}
	return nil
}

func matchExpectedAt(dirFD int, name string, expected *diskEnvelope) bool {
	if expected == nil {
		return false
	}
	fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return false
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || uint64(st.Dev) != expected.dev || uint64(st.Ino) != expected.ino ||
		st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Size <= 0 || st.Size > maxRecordBytesDefault {
		return false
	}
	document := make([]byte, int(st.Size))
	for offset := 0; offset < len(document); {
		n, readErr := unix.Read(fd, document[offset:])
		if readErr != nil || n == 0 {
			return false
		}
		offset += n
	}
	return sha256.Sum256(document) == expected.digest
}
