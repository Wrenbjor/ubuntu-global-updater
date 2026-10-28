"""Local host binding without cloud metadata/network calls (Python3.6)."""
import re,uuid
from pathlib import Path

class IdentityError(Exception):pass

def bounded_text(path):
 with path.open('r') as stream:value=stream.read(257)
 if len(value)>256:raise IdentityError('host_identity_file_too_large')
 return value.strip().lower()

def capture(root=Path('/')):
 root=Path(root)
 machine=bounded_text(root/'etc/machine-id')
 if not re.fullmatch('[0-9a-f]{32}',machine) or machine=='0'*32:
  raise IdentityError('valid_local_machine_id_required')
 firmware=None;path=root/'sys/class/dmi/id/product_uuid'
 try:raw=bounded_text(path)
 except FileNotFoundError:raw=''
 except OSError:raise IdentityError('firmware_identity_unreadable')
 if raw:
  try:value=uuid.UUID(raw)
  except ValueError:raise IdentityError('firmware_identity_malformed')
  if value.int not in (0,(1<<128)-1):firmware=str(value)
 return dict(machine_id=machine,firmware_uuid=firmware)

def verify(recorded,root=Path('/')):
 if type(recorded) is not dict or set(recorded)!={'machine_id','firmware_uuid'}:
  raise IdentityError('recorded_host_binding_invalid')
 current=capture(root)
 if recorded!=current:raise IdentityError('host_identity_drift')
 return True
