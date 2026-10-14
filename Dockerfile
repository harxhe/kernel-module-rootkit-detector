# Linux build/test environment for the Kernel Module Rootkit Detector.
# Usage: docker build -t kmrd-detector . && docker run --rm kmrd-detector
FROM gcc:13

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Default: full verification = normal build + unit + integration tests,
# then the same suite again under AddressSanitizer/UBSan, plus fuzzing.
CMD ["make", "check"]
