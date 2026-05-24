FROM python:3.11-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY samples ./samples
COPY config ./config
RUN pip install --no-cache-dir -e .
ENTRYPOINT ["aws-cloud-security-scanner"]
CMD ["analyze", "--iam", "samples/iam_policies", "--cloudtrail", "samples/cloudtrail/cloudtrail_events.json", "--guardduty", "samples/guardduty/guardduty_findings.json", "--access-analyzer", "samples/access_analyzer/findings.json"]
