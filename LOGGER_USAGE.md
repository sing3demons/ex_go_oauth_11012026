# วิธีใช้งาน Logger Pool

## สรุป

Logger ใหม่ใช้ **Pool Pattern** เพื่อ reuse logger instances แทนการสร้าง logger ใหม่ทุก request ซึ่งจะช่วย:
- ✅ ประหยัด memory และ GC overhead
- ✅ ป้องกัน race condition ระหว่าง request
- ✅ แชร์ file writers และ config ระหว่าง logger instances
- ✅ ไม่ต้อง New logger ใหม่ทุก request

## การใช้งาน

### 1. ไม่ต้องทำอะไรเพิ่มเติมใน main.go

โค้ดปัจจุบันใช้งานได้เลย เพราะ `NewMicroservice` จะสร้าง parent logger ให้อัตโนมัติ:

```go
func main() {
    godotenv.Load()
    cfg := config.NewConfigManager()
    cfg.LoadDefaults()
    
    // ... database, redis setup ...
    
    // NewMicroservice จะสร้าง parent logger ให้อัตโนมัติ
    app := kp.NewMicroservice(cfg)
    
    // ... routes ...
    
    app.Start()
}
```

### 2. ใน Handler ใช้งานปกติ

```go
app.GET("/test", func(ctx *kp.Ctx) {
    // Logger จะถูก Clone มาให้แต่ละ request อัตโนมัติ
    ctx.L("test_handler")
    
    // ใช้งานปกติ
    ctx.Log.Info(logAction.PROCESS("processing data"), map[string]any{
        "data": "example",
    })
    
    // Flush จะ Release logger กลับไปยัง pool อัตโนมัติ
    ctx.JSON(http.StatusOK, map[string]any{
        "message": "success",
    })
})
```

### 3. การทำงานภายใน

```
Request → newMuxContext → parentLogger.Clone() → Ctx.Log
                                                     ↓
                                              ใช้งานใน handler
                                                     ↓
                                              Flush/FlushError
                                                     ↓
                                              Release() → คืนกลับ pool
```

## ข้อสังเกต

1. **ไม่ต้อง New logger ใน middleware อีกต่อไปแล้ว** - `newMuxContext` จะ Clone ให้อัตโนมัติ
2. **ไม่ต้อง defer Release()** - Flush/FlushError จะเรียก Release() ให้อัตโนมัติ
3. **แต่ละ request มี logger instance แยกกัน** - ไม่มี race condition
4. **แชร์ file writers** - ไม่เปิดไฟล์ใหม่ทุก request

## ตัวอย่างการใช้งานขั้นสูง

### Clone Logger สำหรับ Goroutine

หากต้องการใช้ logger ใน goroutine แยก:

```go
app.GET("/async", func(ctx *kp.Ctx) {
    ctx.L("async_handler")
    
    // Clone logger สำหรับ goroutine
    bgLogger := ctx.Log.Clone()
    
    go func() {
        defer bgLogger.Release() // ต้อง Release เอง เพราะไม่มี Flush
        
        bgLogger.Info(logAction.PROCESS("background task"), map[string]any{
            "task": "example",
        })
    }()
    
    ctx.JSON(http.StatusOK, map[string]any{
        "message": "started",
    })
})
```

### ใช้ Logger แบบ Standalone

หากต้องการ logger ที่ไม่ใช่ pool (เช่น service layer):

```go
// สร้าง logger แยก (ไม่ใช้ pool)
serviceLogger := logger.NewLogger("my-service", "1.0.0")
defer serviceLogger.Close()

// ใช้งานตามปกติ
serviceLogger.SetSessionID(sessionID)
serviceLogger.Info(logAction.PROCESS("service operation"), data)
serviceLogger.Flush(200, "success")
// ไม่มี Release() เพราะไม่ได้มาจาก pool
```

## Pool Configuration

Pool ใช้ `sync.Pool` ของ Go ซึ่ง:
- Auto-scale ตามจำนวน request
- GC จะเคลียร์ instances ที่ไม่ได้ใช้งาน
- Thread-safe โดยอัตโนมัติ

## Migration จากโค้ดเดิม

โค้ดเดิมที่ใช้งานอยู่จะยังทำงานได้ปกติ เพราะ:
- `NewLogger()` ยังคงใช้งานได้เหมือนเดิม
- เพิ่มเฉพาะ `Clone()` และ `Release()` methods
- Backward compatible 100%
