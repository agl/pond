#!/usr/bin/perl

$name = "diceware_words";

open (my $of, ">", "$name.go");
print $of <<_EoS_;
package diceware

var $name = []string{
_EoS_

open(my $if, "<", "$name.asc")|| die "couldn't open $wordlist\n";
while (<$if>) {
	while (m/\d{5}\t(\S+)/g) {
		$w = $1;
		$w =~ s/\"/\\\"/;
		print $of "\"$w\",\n";
	}
}
close(F);

print $of <<_EoS_;
}
_EoS_
