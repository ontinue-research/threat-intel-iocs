# AI/LLM Pattern Detection Results

**Program:** voidlink-implant  
**Total Matches:** 28

---

## HIGH-WEIGHT MATCHES

### Address: 010eb2b0 (Weight: 4)
**Pattern:** voidlink_plugin  
**Matched:** 'Plugin loaded'  
**Context:**
```
ailed
[PLUGIN_LOAD] Plugin loaded successfully!

[PLUGIN_EXEC_ROUTE] 
```

---

### Address: 010eb2b0 (Weight: 4)
**Pattern:** voidlink_plugin  
**Matched:** 'Plugin loaded'  
**Context:**
```
failed
[PLUGIN_RUN] Plugin loaded successfully
[PLUGIN_RUN] Final args: [PLUGIN_RUN
```

---

### Address: 010f497d (Weight: 4)
**Pattern:** voidlink_module_registry  
**Matched:** 'Module registry'  
**Context:**
```
  Module registry initialized, all modules ready
```

---

### Address: 010f7ad8 (Weight: 5)
**Pattern:** voidlink_base_components  
**Matched:** 'Base components'  
**Context:**
```
  Base components initialized
```

---

### Address: 010fae1b (Weight: 5)
**Pattern:** phase_numbering  
**Matched:** 'Phase 4:'  
**Context:**
```
Phase 4: Verifying module functionality...
```

---

### Address: 010fae46 (Weight: 5)
**Pattern:** phase_numbering  
**Matched:** 'Phase 2:'  
**Context:**
```
Phase 2: Initializing module registry...
```

---

### Address: 010fae46 (Weight: 4)
**Pattern:** voidlink_module_registry  
**Matched:** 'module registry'  
**Context:**
```
ase 2: Initializing module registry...
```

---

### Address: 010fae6f (Weight: 5)
**Pattern:** phase_numbering  
**Matched:** 'Phase 1:'  
**Context:**
```
Phase 1: Initializing base components...
```

---

### Address: 010fae6f (Weight: 4)
**Pattern:** verbose_init_ellipsis  
**Matched:** 'Initializing base components...'  
**Context:**
```
Phase 1: Initializing base components...
```

---

### Address: 010fae6f (Weight: 5)
**Pattern:** voidlink_base_components  
**Matched:** 'base components'  
**Context:**
```
ase 1: Initializing base components...
```

---

### Address: 010fae98 (Weight: 5)
**Pattern:** phase_numbering  
**Matched:** 'Phase 3:'  
**Context:**
```
Phase 3: Activating stealth features...
```

---

### Address: 010faef7 (Weight: 5)
**Pattern:** phase_numbering  
**Matched:** 'Phase 8:'  
**Context:**
```
Phase 8: Exit cleanup...
```

---

### Address: 010faf10 (Weight: 5)
**Pattern:** phase_numbering  
**Matched:** 'Phase 5:'  
**Context:**
```
Phase 5: Initializing C2 connection...
```

---

### Address: 010faf37 (Weight: 5)
**Pattern:** phase_numbering  
**Matched:** 'Phase 6:'  
**Context:**
```
Phase 6: Starting C2 connection...
```

---

### Address: 010faf5a (Weight: 5)
**Pattern:** phase_numbering  
**Matched:** 'Phase 0:'  
**Context:**
```
Phase 0: Loading runtime configuration...
```

---

## ALL STRING MATCHES

| Pattern | Address | Matched Text |
|---------|---------|--------------|
| bracket_debug | 010eacc0 | '[DEBUG] ' |
| bracket_debug | 010eacc0 | '[DEBUG] ' |
| bracket_debug | 010eacc0 | '[DEBUG] ' |
| bracket_debug | 010eacc0 | '[DEBUG] ' |
| bracket_debug | 010eacc0 | '[DEBUG] ' |
| bracket_debug | 010eacc0 | '[DEBUG] ' |
| bracket_debug | 010eacc0 | '[DEBUG] ' |
| voidlink_plugin | 010eb2b0 | 'Plugin loaded' |
| voidlink_plugin | 010eb2b0 | 'Plugin loaded' |
| verbose_error_failed | 010edebf | 'Failed to send result:' |
| verbose_error_failed | 010f0e24 | 'Failed to spawn shell:' |
| verbose_error_failed | 010f41e0 | 'Failed to send result:' |
| voidlink_module_registry | 010f497d | 'Module registry' |
| bracket_asterisk | 010f4d0b | '[*]' |
| voidlink_base_components | 010f7ad8 | 'Base components' |
| phase_numbering | 010fae1b | 'Phase 4:' |
| verbose_verify | 010fae1b | 'Verifying module functionality' |
| phase_numbering | 010fae46 | 'Phase 2:' |
| voidlink_module_registry | 010fae46 | 'module registry' |
| phase_numbering | 010fae6f | 'Phase 1:' |
| verbose_init_ellipsis | 010fae6f | 'Initializing base components...' |
| verbose_init | 010fae6f | 'Initializing base components' |
| voidlink_base_components | 010fae6f | 'base components' |
| phase_numbering | 010fae98 | 'Phase 3:' |
| phase_numbering | 010faef7 | 'Phase 8:' |
| phase_numbering | 010faf10 | 'Phase 5:' |
| phase_numbering | 010faf37 | 'Phase 6:' |
| phase_numbering | 010faf5a | 'Phase 0:' |

---

## PATTERN SUMMARY

| Pattern | Weight | Count |
|---------|--------|-------|
| phase_numbering | 5 | 8 |
| bracket_debug | 2 | 7 |
| verbose_error_failed | 3 | 3 |
| voidlink_plugin | 4 | 2 |
| voidlink_module_registry | 4 | 2 |
| voidlink_base_components | 5 | 2 |
| verbose_verify | 3 | 1 |
| verbose_init_ellipsis | 4 | 1 |
| bracket_asterisk | 2 | 1 |
| verbose_init | 3 | 1 |

---