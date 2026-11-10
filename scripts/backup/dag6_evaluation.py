"""Stored DAG6 evaluation integrity, without issuing source read approval.

The backup adapter authenticates the exact physical inventory and every typed
logical node. This module projects those retained logical roots and reuses the
ordinary frozen-evaluation, original-reference, locator and score checks. It
never executes analysis, accepts a saved preparation as its expectation, or
reuses a restored service guard. The restored service must still perform its
own full source verification before serving the run.
"""
from cpag_core import evaluation_bundle
from cpag_core.evaluation_shared import adapt_reader, reader_context

STATUS = 'stored_evaluation_integrity_only_source_approval_pending'


def _storage_reader(output):
    # Keep this import lazy: the legacy backup reader does not need a DAG6
    # module, and neither an evaluation document nor a DB row supplies readers.
    import dag6
    return dag6.open_storage_reader(output)


def adapt_preparation(output, *, batch, sample_sha256, projection='dual'):
    """Independently derive a prepared-document expectation from stored roots.

    The caller checks job/publication/attempt/profile/original input ownership
    before selecting this adapter, and compares the complete returned object
    with the actual bounded database bytea. No preparation bytes enter here.
    """
    with _storage_reader(output) as reader:
        return adapt_reader(reader, batch=batch, sample_sha256=sample_sha256,
                            projection=projection)


def verify_document(document, output):
    """Check a saved sidecar against immutable DAG6 roots and reference bytes.

    A temporary local reader context only chooses the retained projection for
    the existing verifier. It does not set the shared service approval context,
    issue a capability, skip storage authentication or publish any trust state.
    """
    with _storage_reader(output) as reader, reader_context(output, reader):
        result = evaluation_bundle.verify_document(document, output)
    return dict(result, backup_evaluation_audit={
        'status': STATUS,
        'source_verification_executed': False,
        'source_approval_issued': False,
        'reference_status': result['result']['bundle_binding']['reference_status'],
        'scope': ('stored typed logical roots, frozen run/attempt/config/input '
                  'binding, versioned independent-reference contract and scores; '
                  'restored service source verification remains required'),
    })
