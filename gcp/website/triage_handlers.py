"""Triage handlers."""
import logging

from flask import Blueprint, request, jsonify, render_template
from google.cloud import storage

blueprint = Blueprint('triage_handlers', __name__)

ALLOWED_BUCKETS = {'cve-osv-conversion', 'osv-test-cve-osv-conversion'}

_STORAGE_CLIENT = None


def get_storage_client():
  """Get storage client."""
  global _STORAGE_CLIENT  # pylint: disable=global-statement
  if _STORAGE_CLIENT is None:
    _STORAGE_CLIENT = storage.Client()
  return _STORAGE_CLIENT


@blueprint.route('/triage')
def triage_index():
  """Triage index."""
  return render_template('triage.html')


@blueprint.route('/triage/proxy')
def triage_proxy():
  """Proxy to fetch files from GCS buckets or external APIs securely."""
  bucket_name = request.args.get('bucket')
  path = request.args.get('path')
  url = request.args.get('url')

  if url:
    # Validate external URLs
    if not (url.startswith('https://cveawg.cve.org/api/cve/') or
            url.startswith('https://services.nvd.nist.gov/rest/json/cves/2.0') or
            url.startswith('https://raw.githubusercontent.com/CVEProject/cvelistV5/')):
      return jsonify({'error': 'Invalid external URL'}), 403

    import requests
    try:
      response = requests.get(url, timeout=10)
      response.raise_for_status()
      return response.text, 200, {'Content-Type': 'application/json'}
    except Exception as e:
      logging.error('Error fetching from external API: %s', e)
      return jsonify({'error': 'Error fetching from external API'}), 500

  if not bucket_name or not path:
    return jsonify({'error': 'Missing bucket, path, or url parameters'}), 400

  if bucket_name not in ALLOWED_BUCKETS:
    return jsonify({'error': 'Invalid bucket'}), 403

  try:
    bucket = get_storage_client().bucket(bucket_name)
    blob = bucket.blob(path)

    if not blob.exists():
      return jsonify({'error': 'File not found'}), 404

    content = blob.download_as_text()
    return content, 200, {'Content-Type': 'application/json'}

  except Exception as e:  # pylint: disable=broad-exception-caught
    logging.error('Error fetching from GCS: %s', e)
    return jsonify({'error': 'Internal server error'}), 500
