"""This module contains two objects:

   1. Stopper
   2. EvalDict

Stopper
=======
Can measure time intervals.

EvalDict
========
Used to store a dictionary used to evaluate an object as well as store the
 results of the evaluation.

   Rules of the Keys
   -----------------
   1. Keys must have the same name as the attribute they represent.
       e.g. If the object ``foo`` has attribute ``bar``, ``foo.bar`` then key
             for ``bar`` is ``'bar'``.
   2. Keys can be methods or more complex functions as well as multiple keys
       concatenated together.
       e.g. ``'is_global()'``, ``'get_attribs()["href"]'``, ``'owner.id'``.
   3. If a key starts with a special then the special will take its effect and
       the key itself will not include the character.
       List of special characters:

          i.     '#' -- The key wont be evaluated
          ii.    '!' -- The attribute would be tested to not equal the
                          evaluation value

   4. If two or more keys that are virtually the same but starts with
       different special characters they would all conflict and wont be
       evaluated.
       Note: any conflicting keys would be reported in the evaluation report or
              if EvalDict.raise_excs_and_fails() is called.
       e.g. ``'#name'``, ``'!name'``, ``'#!name'`` are virtually the same and
             all represent the key ``'name'``.
   5. Key must not include control characters ad some other characters as well.
       Illegal keys wont be evaluated.
       List of illegal characters: [';','\\n','\\b','\\r','\\']

   Structure of a Report
   ---------------------
   "
   Beginning evaluation of object <secureapp.XML_Objects.REST.User object at
    0x7f932cbadef0>
           Key 'type':
           |       Result of expression 'User.type' is 'user' of type <class 'st
r'>.
           |       'user' != 'local': True
   C       Key 'ip' is conflicting with another and so it was skipped.
           Key 'name()':
   E       |       <class 'TypeError'> exception occurred
           Key 'id':
           |       Result of expression 'User.id' is 1907 of type <class 'int'>.
           |       1907 == 1907: True
   #       Key 'get_attribs()["xmlns:xsi"]' is commented and so is being skipped
on.
           Key 'display_name':
           |       Result of expression 'User.display_name' is 'adam_123' of typ
e <class 'str'>.
   F       |       'adam_123' == 'Adam Delman': False
   C       Key '#ip' is conflicting with another and so it was skipped.
   A total of 7 keys were detected. During the evaluation 1 assertion failed, 2
assertions succeeded, 1 exception occurred and 3 keys were skipped in 0.036 seco
nds.
   "

   At the beginning of every line, if something occurred that is related to that
    line, a character representing the occurrence would appear. The characters
    can be divided to two groups: Characters that appear before key line and
    character that appears before assertion line.
   Before key line:

      'E' -- Exception occurred. If the key failed to execute.
      'C' -- Conflicting key. Expect to see another one if you saw one already.
      '#' -- Skipped key. A notice about the key that was skipped would appear.

   Before assertion line:

      'F' -- Failed assertion. The values asserted would appear in the line.

   Whenever the evaluation is occurring inside a key it would appear one tab
    (\\t) further to the right.

   At the end of the report, unless do_summary = False, a summary of all the
    keys would appear. The sum of all the keys (including conflicting keys and
    commented keys) as well as the break up to failed, succeeded, excepted and
    skipped keys (conflicting are skipped too) would be written in the summary.
    The time it took to finish the evaluation would also appear.

   Raising the Exceptions
   ----------------------
   "
   Exception:
   Failings:
       Explanation of assertions:
       <Chain of key leading to the key in which the assertion failed>
           assert <value from the evaluated object> == <value from the
dictionary>
       ---------------
       'User.display_name'
           assert 'adam_123' == 'Adam Delman'
             - adam_123
             + Adam Delman
   Exceptions:
       'User.name()'
           'str' object is not callable
   conflicts:
       User:
           ip
           #ip
       ---------------
   "
   All the AssertionErrors, the Exceptions raised by bad keys and the clashing
    keys would appear one by one in this order inside a single exception."""
__author__ = 'saar.katz'

import time
from types import MethodType
import re

BASE_DEPTH = 1
ALLOWED_GLOBALS = {'__builtins__': None, 'getattr': getattr}
COMMENT_CHAR = '#'
NEGATIVE_CHAR = '!'
REGEX = re.compile(r'[;\n\r\b=\\]')


class Stopper:
    """
    This class is used as a stopper. Can measure time intervals.
    """

    def __init__(self):
        self._rounds = []
        self.started = False
        self._last = None

    def __len__(self):
        return len(self._rounds)

    def __getitem__(self, item):
        return self._rounds[item]

    def __iter__(self):
        for roun in self._rounds:
            yield roun

    def __str__(self):
        return str(self._rounds)

    def start(self):
        cur_time = time.time()
        if not self.started:
            self.started = True
            self._last = cur_time

    def round(self):
        cur_time = time.time()
        if self.started:
            roun = cur_time - self._last
            self._rounds.append(roun)
            self._last = cur_time

    def stop(self):
        cur_time = time.time()
        if self.started:
            roun = cur_time - self._last
            self._rounds.append(roun)
            self._last = None
            self.started = False

    def elapsed(self):
        cur_time = time.time()
        if self.started:
            return sum(self._rounds) + (cur_time - self._last)
        return sum(self._rounds)

    def clear(self):
        self.__init__()


class EvalDict(dict):
    """
    This class is used to store a dictionary used to evaluate with the attributes of an object by the same names
     as the keys in the provided dictionary.
     EvalDict stores the results of the last evaluation and enables their retrieval later on.
    """

    def __init__(self, iterable=None, **kwargs):
        super().__init__(iterable, **kwargs)
        for key, value in self.items():
            if isinstance(value, dict):
                self[key] = EvalDict(value)

        self.levels = []
        self.fail_count = {'successes': 0, 'failures': 0, 'exceptions': 0,
                           'skipped': 0}
        self.conflicts = self.conflicting_keys()
        self.exceptions = []
        self.failures = []
        self.report = ''
        self.summary = ''

    def __str__(self):
        return 'EvalDict({})'.format(str(super(EvalDict, self)))

    def eval_object_attribs(self, e_object, **kwargs):
        """
        Begin new evaluation of the provided object against the contained dictionary.
        :param e_object: The object that would be evaluated against.
        :keyword depth: Controls the numbers of tabs to push the report string. Defaults to 1.
        :keyword do_report: Controls whether create a report or not. Defaults to True.
        :keyword do_summary: Controls whether create a summary or not. Defaults to True.
        :keyword levels: The path to the evaluated object. Defaults to the object's class name
        :return: A tuple containing the different parts of the result information in the form of
         (report, failed assertions, exceptions, conflicting keys)
        :rtype: (str, list[AssertionError], list[Exception], list[str])
        """
        # Handling keyword arguments.
        depth = kwargs.get('depth', BASE_DEPTH)
        do_report = kwargs.get('do_report', True)
        do_summary = kwargs.get('do_summary', True)
        self.fail_count = kwargs.get('fail_count',
                                     {'successes': 0, 'failures': 0,
                                      'exceptions': 0, 'skipped': 0})
        self.levels = outer_levels = kwargs.get('levels',
                                                [type(e_object).__name__])

        # Reformat the report and summary if either one of them already exists.
        self.report = ''
        self.summary = ''

        stopper = Stopper()
        report_prefix = lambda tab: '|'.join(['\t' for i in range(depth + tab)])
        if do_report and depth == BASE_DEPTH:
            self.report += 'Beginning evaluation of object {}'.format(e_object)

        # Evaluation begins.
        stopper.start()
        for key, value in self.items():
            # If key is conflicting with another, skip it and report the skip.
            if key in self.conflicts:
                if do_report:
                    if not self.report:
                        self.report = 'C{}Key {} is conflicting with another and so it was skipped.'.format(
                            report_prefix(0), repr(key))
                    else:
                        self.report = '\n'.join((self.report,
                                                 'C{}Key {} is conflicting with another and so it was skipped.'.format(
                                                     report_prefix(0),
                                                     repr(key))))
                self.fail_count['skipped'] += 1
                continue
            # If key is commented out skip it and report the skip.
            if key.startswith(COMMENT_CHAR):
                if do_report:
                    if not self.report:
                        self.report = '#' + report_prefix(
                            0) + "Key {} is commented and so has being skipped.".format(
                            repr(key[1:]))
                    else:
                        self.report = '\n'.join((self.report,
                                                 '#' + report_prefix(
                                                     0) + "Key {} is commented and so is being skipped.".format(
                                                     repr(key[1:]))))
                self.fail_count['skipped'] += 1
                continue
            # If not, check for any operation before the key, record it and clean the key.
            elif key.startswith(NEGATIVE_CHAR):
                is_positive = False
                key = key[1:]
            else:
                is_positive = True

            levels = outer_levels[:]
            levels.append(key)

            # if do_report, add the key title to the report
            if do_report:
                if not self.report:
                    self.report = report_prefix(0) + "Key {}:".format(repr(key))
                else:
                    self.report = '\n'.join((self.report, report_prefix(
                        0) + "Key {}:".format(EvalDict.short_repr(key))))

            try:
                # Check for regular expression of the key.
                key_match = REGEX.findall(key)
                if key == '':  # A key can't be an empty string.
                    raise ValueError("A key can't be an empty string.")
                elif key_match:  # Safety first.
                    raise ValueError(
                        r"The key must not contain the characters [;=\] or any control character. key received was {}".format(
                            repr(key)))

                # Getting the object value for the given key.
                expression = "e_object.{}".format(str(key))
                result_value = []  # wrapper to the result of the executed code.
                get_into_result_code = 'attr = {expression}; result_value.append(attr)'

                exec(get_into_result_code.format(expression=expression),
                     # string of the executed code.
                     ALLOWED_GLOBALS,  # globals()
                     {'e_object': e_object,
                      'result_value': result_value})  # locals()

                result_value = result_value[0]


            except Exception as error:
                self.fail_count['exceptions'] += 1
                self.report = '\n'.join((self.report,
                                         "E{}{} exception occurred".format(
                                             report_prefix(1),
                                             EvalDict.short_type(error))))
                error.levels = levels
                self.exceptions.append(error)
                continue

            # if do_report, announce the result of the expression in the report.
            if do_report:
                reported_expression = expression.replace(
                    'e_object.{}'.format(str(key)), '.'.join(levels)) if len(
                    levels) == depth + 1 else expression.replace('e_object',
                                                                 EvalDict.short_repr(
                                                                     e_object))
                self.report = '\n'.join((self.report, report_prefix(1) +
                                         "Result of expression {} is {} of type {}.".format(
                                             repr(reported_expression),
                                             repr(result_value),
                                             EvalDict.short_type(
                                                 result_value))))

            # if value is a dictionary then assume that key is an object.
            if isinstance(value, EvalDict):
                # if do_report, report the attempt to open the result_value as a complex object.
                if do_report:
                    self.report = '\n'.join((self.report, report_prefix(
                        1) + "Inside {}:".format(
                        EvalDict.short_repr(result_value))))

                in_report = value.eval_object_attribs(result_value,
                                                      depth=depth + 1,
                                                      do_report=do_report,
                                                      do_summary=False,
                                                      fail_count=self.fail_count,
                                                      levels=levels)
                if do_report:
                    self.report = '\n'.join((self.report, in_report[0]))
                self.failures.extend(in_report[1])
                self.exceptions.extend(in_report[2])
            else:
                # if do_report, add the assertion into the report
                if do_report:
                    assertion = result_value == value if is_positive else result_value != value
                    self.report = '\n'.join((self.report,
                                             "{}{}{} {}= {}: {}".format(
                                                 '' if assertion else 'F',
                                                 report_prefix(1),
                                                 repr(result_value),
                                                 '=' if is_positive else '!',
                                                 repr(value), assertion)))
                try:
                    if is_positive:
                        assert result_value == value
                    else:
                        assert result_value != value
                except Exception as error:
                    error.levels = levels
                    self.failures.append(error)
                    self.fail_count['failures'] += 1
                else:
                    self.fail_count['successes'] += 1
        stopper.stop()

        # if do_summary == True, then prepare the summary of the report and add it to the end.
        self.summary = self.get_summary(stopper)
        if do_summary:
            report = '\n'.join((self.report, self.summary))
        else:
            report = self.report
        return report, self.failures, self.exceptions, self.conflicts

    def passed(self):
        """
        Answers the question: 'Did the last evaluation passed without any exception of any kind?'
        :return: Whether any exception occurred. True if no exception occurred, otherwise False.
        :rtype: bool
        """
        return not any((self.exceptions, self.failures, self.conflicts))

    def raise_excs_and_fails(self):
        """
        Raises all the exceptions that occurred in a single exception of type Exception.
        If no exception occurred does nothing.
        """
        if self.passed():
            return
        # Construct the exception report as a generic exception.
        e_string = ''
        if self.failures:
            itr = [e_string, 'failures:', '\tExplanation of assertions:',
                   '\t<Chain of key leading to the key in which the assertion failed>',
                   '\t\tassert <value from the evaluated object> == <value from the dictionary>',
                   '\t---------------']
            itr.extend(['\n\t\t'.join(('\t' + repr('.'.join(err.levels)),
                                       '\n\t\t'.join(str(err).split('\n')))) for
                        err in self.failures])
            e_string = '\n'.join(itr)
        if self.exceptions:
            itr = [e_string, 'Exceptions:']
            itr.extend(['\n\t\t'.join(('\t' + repr('.'.join(err.levels)),
                                       '\n\t\t'.join(str(err).split('\n')))) for
                        err in self.exceptions])
            e_string = '\n'.join(itr)
        if self.conflicts:
            itr = [e_string, 'conflicts:']
            itr.extend(
                ['\t' + '\n\t'.join((self.conflicting_keys_string_lines()))])
            e_string = '\n'.join(itr)
        raise Exception(e_string)

    def conflicting_keys(self):
        """
        :return: The list of all the keys that are considered conflicting as described in the rules of the keys.
        :rtype: list[str]
        """
        keys = {}
        conflicting_keys = []
        for key in self.keys():
            pattern = re.compile('[!#]*')
            m = pattern.match(key)
            if m:
                striped_key = key.lstrip('#!')
            else:
                striped_key = key
            if striped_key not in keys.keys():
                keys[striped_key] = [key]
            else:
                keys[striped_key].append(key)
        for cks in keys.values():
            if len(cks) > 1:
                conflicting_keys.extend(cks)
                conflicting_keys.append('---------------')
        return conflicting_keys

    def conflicting_keys_string_lines(self):
        """
        :return: A string representing all the conflicts of keys in dictionary as described in the rules of the keys.
        :rtype: str
        """
        if self.conflicts:
            all_conflicts = ['.'.join(self.levels) + ':']
            all_conflicts.extend(
                ['\t' + line if line != '---------------' else line for line in
                 self.conflicts])
            for value in self.values():
                if isinstance(value, EvalDict):
                    all_conflicts.extend(value.conflicting_keys_string_lines())
            return all_conflicts
        return []

    def get_report(self, summary=True):
        """
        Get the report of the last evaluation.
        :param summary: Whether or not to include the summary in the returned report.
        :return: The report of the last evaluation.
        """
        if summary:
            return '\n'.join((self.report, self.get_summary()))
        else:
            return self.report

    def get_summary(self, stopper=None):
        """
        Get the summary of the last evaluation. Recreates the summary if it doesn't exists or a new stopper is provided
        The provided stopper must have a method stopper.elapsed() that returns an integer representing of the
        time it took to execute the evaluation in seconds.
        :param stopper: The stopper that contains the time of the evaluation
        :return: A string of the summary
        :rtype: str
        """
        if self.summary and not stopper:
            return self.summary
        else:
            total_keys = 0
            for c_value in self.fail_count.values():
                total_keys += c_value
            summary_message = 'A total of {} key{} detected.'.format(total_keys,
                                                                     ' was' if total_keys == 1 else 's were')
            message = []
            if self.fail_count['failures']:
                message.append(
                    '{} assertion{} failed'.format(self.fail_count['failures'],
                                                   '' if self.fail_count[
                                                             'failures'] == 1 else 's'))
            if self.fail_count['successes']:
                message.append('{} assertion{} succeeded'.format(
                    self.fail_count['successes'],
                    '' if self.fail_count['successes'] == 1 else 's'))
            if self.fail_count['exceptions']:
                message.append('{} exception{} occurred'.format(
                    self.fail_count['exceptions'],
                    '' if self.fail_count['exceptions'] == 1 else 's'))
            if self.fail_count['skipped']:
                message.append(
                    '{} key{} skipped'.format(self.fail_count['skipped'],
                                              ' was' if self.fail_count[
                                                            'skipped'] == 1 else 's were'))

            if len(message) == 1:
                summary_message += ' During the evaluation '
                summary_message += message[0]
                if stopper:
                    rounded_time = round(stopper.elapsed(), 3)
                    summary_message += ' in {} second{}.'.format(rounded_time,
                                                                 '' if rounded_time == 1 else 's')
                else:
                    summary_message += '.'
            elif len(message) > 1:
                summary_message += ' During the evaluation '
                summary_message += ', '.join(
                    [message[i] for i in range(len(message) - 1)])
                summary_message += ' and {}'.format(message[-1])
                if stopper:
                    rounded_time = round(stopper.elapsed(), 3)
                    summary_message += ' in {} second{}.'.format(rounded_time,
                                                                 '' if rounded_time == 1 else 's')
                else:
                    summary_message += '.'
            elif len(message) == 0:
                if stopper:
                    rounded_time = round(stopper.elapsed(), 3)
                    summary_message += ' Complete in total of {} second{}.'.format(
                        rounded_time, '' if rounded_time == 1 else 's')
            return summary_message

    @staticmethod
    def short_type(obj, **kwargs):
        n = 1
        typ = str(type(obj))
        typs = typ.split('.')
        if len(typs) > n + 1 > 1:
            fpart = '.'.join([typs[i] for i in range(n)])
            lpart = typs[-1]
            return '...'.join((fpart, lpart))
        else:
            return typ

    @staticmethod
    def short_repr(obj, **kwargs):
        n = 1
        objc = repr(obj)
        if isinstance(obj.__repr__, MethodType):
            return objc
        else:
            objcs = objc.split('.')
            if len(objcs) > n + 1 > 1:
                fpart = '.'.join([objcs[i] for i in range(n)])
                lpart = objcs[-1]
                return '...'.join((fpart, lpart))
            else:
                return objc
