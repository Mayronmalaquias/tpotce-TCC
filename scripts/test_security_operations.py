import datetime as dt
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import security_operations as ops


class NotifyFailureTests(unittest.TestCase):
    def test_rate_limited_per_unit(self):
        config = {'instance_id': 'i-test'}
        start = dt.datetime(2026, 10, 2, 12, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(ops, 'publish') as publish:
            state = Path(directory)
            unit = 'beeia-integrity.service'
            self.assertTrue(ops.notify_failure(config, state, unit, start))
            self.assertFalse(ops.notify_failure(config, state, unit, start + dt.timedelta(hours=1)))
            self.assertTrue(ops.notify_failure(config, state, 'beeia-backup.service',
                                               start + dt.timedelta(hours=1)))
            self.assertTrue(ops.notify_failure(config, state, unit, start + dt.timedelta(hours=6, seconds=1)))
            self.assertEqual(publish.call_count, 3)

    def test_corrupt_marker_does_not_block_alert(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(ops, 'publish') as publish:
            state = Path(directory)
            (state / 'notify-x.service.json').write_text('{"last_sent_at": "garbage"}')
            self.assertTrue(ops.notify_failure({'instance_id': 'i'}, state, 'x.service',
                                               dt.datetime.now(dt.timezone.utc)))
            publish.assert_called_once()


if __name__ == '__main__':
    unittest.main()
