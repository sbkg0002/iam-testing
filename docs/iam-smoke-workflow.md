# IAM Smoke Testing Workflow

```mermaid
graph TD
    A[Start] --> B[Create Test Resources]
    B --> C[IAM Role]
    B --> D[S3 Bucket]
    C --> E[Assume IAM Role]
    E --> F[Get Temporary Credentials]
    E --> G[Execute API Calls]
    G --> H[S3 Operations]
    G --> I[EC2 Operations]
    G --> J[IAM Operations]
    J --> K[Assert Results]
    K --> L[Success Tests]
    K --> M[Failure Tests]
    K --> N[End]
    
    classDef default color:black
    style A fill:#d5e8d4,stroke:#82b366
    style B fill:#dae8fc,stroke:#6c8ebf
    style C fill:#ffe6cc,stroke:#d79b00
    style D fill:#ffe6cc,stroke:#d79b00
    style E fill:#dae8fc,stroke:#6c8ebf
    style F fill:#e1d5e7,stroke:#9673a6
    style G fill:#dae8fc,stroke:#6c8ebf
    style H fill:#e1d5e7,stroke:#9673a6
    style I fill:#e1d5e7,stroke:#9673a6
    style J fill:#e1d5e7,stroke:#9673a6
    style K fill:#dae8fc,stroke:#6c8ebf
    style L fill:#d5e8d4,stroke:#82b366
    style M fill:#f8cecc,stroke:#b85450
    style N fill:#d5e8d4,stroke:#82b366
```

## Process Flow Description

1. **Start**: Begin the smoke test process

2. **Create Test Resources**:
   - Create an IAM role with necessary permissions
   - Optionally apply a permission boundary
   - Create an S3 bucket for testing

3. **Assume IAM Role**:
   - Use AWS STS to assume the test role
   - Obtain temporary security credentials

4. **Execute API Calls**:
   - Perform operations against various AWS services:
     - S3 operations (list bucket, get object)
     - EC2 operations (describe instances)
     - IAM operations (list roles)

5. **Assert Results**:
   - For success tests: verify the operation succeeded
   - For failure tests: verify the operation was denied

6. **End**: Complete the smoke test process
