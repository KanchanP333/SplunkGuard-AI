``` mermaid

flowchart TB
    %% Define Styling
    classDef splunk fill:#222,stroke:#ff66cc,stroke-width:2px,color:#fff
    classDef python fill:#222,stroke:#33ccff,stroke-width:2px,color:#fff
    classDef ollama fill:#222,stroke:#00ff99,stroke-width:2px,color:#fff

    subgraph s3["Splunk Enterprise"]
        direction TB
        s4["Log"]:::splunk
        s5["HEC"]:::splunk
        s6["Dashboard"]:::splunk
    end

    subgraph s7["Python Backend"]
        direction TB
        s8["API"]:::python
        s9["Telemetry"]:::python
        s10["Formatter"]:::python
    end

    subgraph s11["Local LLM"]
        direction TB
        s12["Agent1"]:::ollama
        s13["Agent2"]:::ollama
    end

    %% Workflow execution connections
    s4 -- "s14" --> s8
    s8 -- "s15" --> s9
    s9 -. "3. Query CPU Metrics" .-> s4
    s8 -- "s16" --> s12
    s12 -- "s17" --> s13
    s13 -- "s18" --> s10
    s10 -- "s19" --> s5
    s5 -- "s20" --> s6

```
