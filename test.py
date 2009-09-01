import time
import udns
import unittest


class InterfaceTestCase(unittest.TestCase):
    def test_000(self):
        pass # simply import work

    def test_001(self):
        udns.Resolver(False, True)

    def test_002(self):
        udns.Resolver(False)

    def test_003(self):
        udns.Resolver()

    def test_011(self):
        R = udns.Resolver()
        R.active

    def test_012(self):
        R = udns.Resolver()
        R.status

    def test_013(self):
        R = udns.Resolver()
        R.sock

    def test_021(self):
        R = udns.Resolver()
        R.submit_a4("localhost", lambda r, _data: None)

    def test_022(self):
        R = udns.Resolver()
        q = R.submit_a4("localhost", lambda r, _data: None)
        R.cancel(q)

    def test_024(self):
        R = udns.Resolver()
        R.close()

    def test_025(self):
        R = udns.Resolver()
        R.submit_a4("localhost", lambda r, _data: None)
        R.close()

    def test_031(self):
        R = udns.Resolver()
        q = R.submit_a4("localhost", lambda r, _data: None)
        q.is_completed

    def test_032(self):
        R = udns.Resolver()
        q = R.submit_a4("localhost", lambda r, _data: None)
        q.cancel()


class BasicTestCase(unittest.TestCase):
    def setUp(self):
        self.R = udns.Resolver()

    def test_async_resolve_001(self):
        TIMEOUT = 5 # sec
        flags = []
        def cb(r, _data):
            flags.append(r)
        self.R.submit_a4("localhost", cb)
        # simulation of dumb event loop
        for _ in xrange(TIMEOUT * 100):
            self.R.ioevent()
            self.R.timeouts(1)
            time.sleep(0.01)
            if not self.R.active:
                break
        self.assertTrue(flags)


if __name__ == "__main__":
    unittest.main()
