FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port
EXPOSE 8000

# Start command - use PORT environment variable with fallback
CMD uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}
```

**Промяна:** Последният ред използва `${PORT:-8000}` което означава "използвай $PORT ако съществува, иначе 8000"

---

## 📝 Редактирай Dockerfile в GitHub:

1. Отвори https://github.com/stefony/cyberguardian-backend-v2/blob/main/Dockerfile
2. Редактирай последния ред от:
```
   CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```
   
   На:
```
   CMD uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}
