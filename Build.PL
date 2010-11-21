{ use 5.006; }
use warnings;
use strict;

use Module::Build;

Module::Build->subclass(code => q{
	sub compile_c {
		my($self, $file, %args) = @_;
		# need PERL_CORE for working HINTS_REFCNT_LOCK and
		# GRAMPROG constant
		$args{defines} = { %{$args{defines} || {}},
			PERL_CORE => 1,
		};
		return $self->SUPER::compile_c($file, %args);
	}
})->new(
	module_name => "Parse::Perl",
	license => "perl",
	configure_requires => {
		"Module::Build" => 0,
		"perl" => "5.008004",
		"strict" => 0,
		"warnings" => 0,
	},
	build_requires => {
		"ExtUtils::CBuilder" => "0.15",
		"Module::Build" => 0,
		"Test::More" => 0,
		"perl" => "5.008004",
		"strict" => 0,
		"warnings" => 0,
	},
	requires => {
		"Exporter" => 0,
		"XSLoader" => 0,
		"parent" => 0,
		"perl" => "5.008004",
		"strict" => 0,
		"warnings" => 0,
	},
	dynamic_config => 0,
	meta_add => { distribution_type => "module" },
	create_makefile_pl => "passthrough",
	sign => 1,
)->create_build_script;

1;
