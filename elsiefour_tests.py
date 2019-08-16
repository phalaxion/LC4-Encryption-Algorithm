"""Test suite for my implementation of the elsiefour algorithm"""

import unittest
from elsiefour_algorithm import shift_row, shift_column, shift_s_box, elsie_four


class Test_Elsiefour(unittest.TestCase):

    def test_shift_row(self):
        key = "#_23456789abcdefghijklmnopqrstuvwxyz"
        s_box = [key[:6], key[6:12],
                 key[12:18], key[18:24],
                 key[24:30], key[30:]]

        expected_key = "5#_2346789abcdefghijklmnopqrstuvwxyz"
        expected_s_box = [expected_key[:6], expected_key[6:12],
                          expected_key[12:18], expected_key[18:24],
                          expected_key[24:30], expected_key[30:]]

        s_box = shift_row(s_box, 0)
        self.assertEqual(s_box, expected_s_box, '0th row shift unsuccessful')

    def test_shift_column(self):
        key = "#_23456789abcdefghijklmnopqrstuvwxyz"
        s_box = [key[:6], key[6:12],
                 key[12:18], key[18:24],
                 key[24:30], key[30:]]

        expected_key = "u_2345#789ab6defghcjklmnipqrstovwxyz"
        expected_s_box = [expected_key[:6], expected_key[6:12],
                          expected_key[12:18], expected_key[18:24],
                          expected_key[24:30], expected_key[30:]]

        s_box = shift_column(s_box, 0)
        self.assertEqual(s_box, expected_s_box, '0th column shift unsuccessful')

    def test_shift_s_box(self):
        key = "#_23456789abcdefghijklmnopqrstuvwxyz"
        s_box = [key[:6], key[6:12],
                 key[12:18], key[18:24],
                 key[24:30], key[30:]]

        expected_s_box = ["#_w345", "b6289a", "cd7fgh",
                          "ijelmn", "opkrst", "uvqxyz"]
        s_box, marker = shift_s_box(s_box, '#', (2, 1), 'e')
        self.assertEqual(s_box, expected_s_box, 's-box shifted incorrectly')
        self.assertEqual(marker, '7', 'Marker Shifted Incorrectly: Should be 7')

    def test_elsie_four(self):
        # Testing correct Results
        result = elsie_four("#_23456789abcdefghijklmnopqrstuvwxyz", "hello_world")
        self.assertEqual(result, 'hywh7kjm5d5', 'Failed Encryption should be: "hywh7kjm5d5"')

        result = elsie_four("#_23456789abcdefghijklmnopqrstuvwxyz", "%hywh7kjm5d5")
        self.assertEqual(result, 'hello_world', 'Failed Encryption should be: "hello_world"')

        # Testing to ensure key/message validity checks work
        result = elsie_four("#_23456789abcdefghijklmnopqrstuvwxyz1", "hello_world")
        self.assertEqual(result, '--Error: Please provide a key of length 36--', 'keys longer than 36 should not be allowed')

        result = elsie_four("#_23456789abcdefghijklmnopqrstuvwxy", "hello_world")
        self.assertEqual(result, '--Error: Please provide a key of length 36--', 'keys shorter than 36 should not be allowed')

        result = elsie_four("#_23456789abcdefghijklmnopqrstuvyyyz", "hello_world")
        self.assertEqual(result, '--Error: Please compose your key of unique characters--', 'keys/message should have only unique characters')

        result = elsie_four("#_23456789abcdefghijklmnopqrstuvw@^&", "hello_world")
        self.assertEqual(result, '--Error: invalid characters in key/message--', 'keys/message should only have characters from the specified alphabet')

if __name__ == '__main__':
    unittest.main()
