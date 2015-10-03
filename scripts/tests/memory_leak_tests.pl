#!/usr/bin/perl
###############################################################################
 # File: memory_leak_tests.pl
 # Description: Perl script to detect memory leaks in the uMQTT tests.
 # 
 # Author: Steven Swann - swannonline@googlemail.com
 #
 # Copyright (c) swannonline, 2013-2014
 #
 # This file is part of uMQTT.
 #
 # uMQTT is free software: you can redistribute it and/or modify
 # it under the terms of the GNU General Public License as published by
 # the Free Software Foundation, either version 3 of the License, or
 # (at your option) any later version.
 #
 # uMQTT is distributed in the hope that it will be useful,
 # but WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 # GNU General Public License for more details.
 #
 # You should have received a copy of the GNU General Public License
 # along with uMQTT.  If not, see <http://www.gnu.org/licenses/>.
 #
##############################################################################
use strict;
use warnings;

use Getopt::Std;
use Text::Table;
use File::Copy qw(move);
use Carp;
use Config;

use constant MEMORY_LEAK_ERR_RET => 255;

my $test_dir = './results';

my $valgrind_cmd = "valgrind --leak-check=full --track-origins=yes --error-exitcode=" . MEMORY_LEAK_ERR_RET . " ";

my $ret = 0;
my $test_count = 0;
my $fail_count = 0;


my $test_no = 1;
my $name = "";

my @results;
my $exp_rc = 0;

# Table printing code function found:
#   http://use.perl.org/use.perl.org/_Ovid/journal/36762.html
sub make_table {
  my ( $headers, $rows ) = @_;

  my @rule      = qw(- +);
  my @headers   = \'| ';
  push @headers => map { $_ => \' | ' } @$headers;
  pop  @headers;
  push @headers => \' |';

  unless ('ARRAY' eq ref $rows
      && 'ARRAY' eq ref $rows->[0]
      && @$headers == @{ $rows->[0] }) {
    croak(
        "make_table() rows must be an AoA with rows being same size as headers"
        );
  }
  my $table = Text::Table->new(@headers);
  $table->rule(@rule);
  $table->body_rule(@rule);
  $table->load(@$rows);

  return $table->rule(@rule),
         $table->title,
         $table->rule(@rule),
         map({ $table->body($_) } 0 .. @$rows),
         $table->rule(@rule);
}

# Function to return signal name from number 
# edited from: http://perldoc.perl.org/Config.html
sub get_signal_name
{
  my ($signum) = @_;

  my %sig_num;
  my @sig_name;
  unless($Config{sig_name} && $Config{sig_num}) {
    die "No sigs?";
  } else {
    my @names = split ' ', $Config{sig_name};
    @sig_num{@names} = split ' ', $Config{sig_num};
    foreach (@names) {
      $sig_name[$sig_num{$_}] ||= $_;
    }   
  }
  return $sig_name[$signum];
}

# Function to perform test and print result
# \param $print when set prints test name without running test
# \param $run test number of test which should be executed, null for all tests
sub run_test
{
  my ($cmd, $num, $name, $exp_res, $result_ref) = @_;

  my $status = ' ';

  $cmd = "$cmd 2>&1";

  my $out = `$cmd`;
  my $ret = $? >> 8;
  my $exit_state = $? & 127;

  print $out;

  if ($exit_state)
  {
    my $signame = get_signal_name($exit_state);
    $status = "Process Died: SIG$signame";
    print "\n\t\tProcess died with signal: SIG$signame\n";
    print "\n\n\t\t**** FAILED ****\n\n";
  }
  else
  {
    if ($ret == $exp_res)
    {
      print "\n\t\tNo memory errors detected\n";
      print "\t\tExit status: $ret\n";
      print "\n\t\t** PASSED **\n\n";
    }
    else
    {
      if ($ret == MEMORY_LEAK_ERR_RET) 
      {
        $status = 'MemLeak';
        print "\n\t\tERROR: Memory errors detected";
      }
      else
      {
        $status = 'Exit error';
      }

      print "\n\t\tExit status: $ret\n";
      print "\n\n\t\t**** FAILED ****\n\n";
    }
  }
  push(@$result_ref, [$num, $name, $status, $ret, $exp_res]);
  return $ret;
}

# function to print results in a table
# \param @results = @([No, Name, Status, rc, exp_rc, memleak]) 
sub print_result_table
{
  my ($r) = @_;

  print "\n\n\t** Results **\n";
  print make_table(["No", "Name", "Status", "RC", "Expected"], $r);
  print "\n";

  return 0;
}

#
# TEST: uMQTT_tests
#
sub uMQTT_tests
{
  my ($num,$results_ref) = @_;

  my $name = "uMQTT_tests";
  my $exp_rc = 0;
  my $ret = 0;
  my $cmd = $valgrind_cmd . "bin/uMQTT_tests",

  print "\n**** TEST: $num - $name ****\n\n";
  print "\tExec command:\n\t$cmd\n";

  $ret = run_test($cmd, $num, $name, $exp_rc, $results_ref);

  return $ret;
}

#
# TEST: uMQTT_pub_test
#
sub uMQTT_pub_test
{
  my ($num, $results_ref) = @_;

  my $name = "uMQTT_pub_test";
  my $exp_rc = 0;
  my $ret = 0;
  my $cmd = $valgrind_cmd . "bin/uMQTT_pub_test",

  print "\n**** TEST: $num - $name ****\n\n";
  print "\tExec command:\n\t$cmd\n";

  $ret = run_test($cmd, $num, $name, $exp_rc, $results_ref);

  return $ret;
}

#
# START TESTS
#
my $error;

if (uMQTT_tests($test_no++, \@results) != 0)
{
  $error = -1;
}
if (uMQTT_pub_test($test_no++, \@results) != 0)
{
  $error = -1;
}

# END OF TESTS
print_result_table(\@results);

print "\ndone: " . ($error ? "" : "No") . "Errors Detected\n";
exit($error);
