## Summary

<!-- What changed and why. -->

## Security checklist

- [ ] No credentials, API keys, or `.env` files are committed.
- [ ] IAM changes stay scoped; no wildcard actions/resources without a
      documented reason, and the permissions boundary still applies.
- [ ] New data stores/buckets are encrypted and covered by retention/backup.
- [ ] Public access remains blocked.
- [ ] Queue/resource policies pin `aws:SourceArn` and `aws:SourceAccount`.
- [ ] `make test`, `make validate`, and `make security` pass.

## Testing

<!-- Commands or evidence. -->
