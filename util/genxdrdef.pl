#!/usr/bin/env perl
# genxdrdef.pl --- Generate C header file which used by packet-libvirt.[ch]
#
# Copyright (C) 2013 Yuto Kawamura(kawamuray) <kawamuray.dadada@gmail.com>
#
# Author: Yuto Kawamura(kawamuray)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 3
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# For XDR syntax, see http://tools.ietf.org/html/rfc4506#section-6.3
# This script does not strictly check syntax of xdr protocol specification.
# Make sure the specification files you have are correctly compilable with rpcgen(1).
# If something fails with this script in spite of you had confirmed that the `make' with libvirt was succeed,
# please report your error output to kawamuray<kawamuray.dadada@gmail.com>.
use v5.10;
use strict;
use warnings;
use File::Spec;

# TODO: add prefixes for needed things
# TODO: dependencies graph
# TODO: inteligent error message

{
    sub mk_accessor {
        my $caller = caller;
        no strict 'refs';
        for my $f (@_) {
            *{ "$caller\::$f" } = sub {
                my ($self, $v) = @_;

                if (@_ > 1) {
                    $self->{$f} = $v;
                    $self;
                } else {
                    $self->{$f};
                }
            };
        }
    }

    package Sym;
    ::mk_accessor qw/ ident /;

    sub new {
        my ($class, %args) = @_;

        bless { %args }, $class;
    }

    sub bless {
        my ($self, $klass) = @_;

        bless $self, "Sym::$klass"
            if ref($self) ne "Sym::$klass";
        $self;
    }

    package Sym::Type;
    use parent -norequire, 'Sym';
    ::mk_accessor qw/ alias /;

    sub is_primitive { !(shift)->{alias} }

    sub dealias {
        my ($self) = @_;

        $self->is_primitive ? $self : $self->alias->dealias;
    }

    sub subdef {
        my ($self) = @_;

        $self->is_primitive ? undef : $self->dealias->subdef;
    }

    sub metainfo {
        my ($self) = @_;

        $self->is_primitive ? undef : $self->dealias->metainfo;
    }

    sub xdr_type {
        my ($self) = @_;

        if (!$self->is_primitive) {
            return $self->dealias->xdr_type;
        }

        my $type = ref $self;
        if ($type eq __PACKAGE__) {
            $type = $self->ident;
        } else {
            $type =~ s/^.*:://;
        }
        uc($type);
    }

    package Sym::Type::Struct;
    use parent -norequire, 'Sym::Type';
    ::mk_accessor qw/ members /;

    sub subdef { join('_', split /\s/, (shift)->ident).'_members' }

    package Sym::Type::Enum;
    use parent -norequire, 'Sym::Type';
    ::mk_accessor qw/ members /;

    sub subdef { join('_', split /\s/, (shift)->ident).'_members' }

    package Sym::Type::Union;
    use parent -norequire, 'Sym::Type';
    ::mk_accessor qw/ decl case_specs /;

    sub subdef { join('_', split /\s/, (shift)->ident).'_members' }

    package Sym::Type::_Ref; # Abstract
    ::mk_accessor qw/ reftype /;

    # sub dealias {
    #     my ($self) = @_;

    #     my $dealiased = $self->SUPER::dealias;
    #     ref($dealiased)->new(%$dealiased, reftype => $self->reftype->dealias);
    # }

    sub subdef { '&'.(shift)->reftype->ident }

    package Sym::Type::_Ext; # Abstract
    ::mk_accessor qw/ length /;

    sub metainfo { (shift)->length }

    package Sym::Type::Array; # aka Variable-Length Array
    use parent -norequire, qw{ Sym::Type::_Ref Sym::Type::_Ext Sym::Type };

    package Sym::Type::Vector; # aka Fixed-Length Array
    use parent -norequire, qw{ Sym::Type::_Ref Sym::Type::_Ext Sym::Type };

    package Sym::Type::Pointer;
    use parent -norequire, qw{ Sym::Type::_Ref Sym::Type };

    package Sym::Type::String;
    use parent -norequire, qw{ Sym::Type::_Ext Sym::Type };

    package Sym::Type::Bytes; # aka Variable-Length Opaque
    use parent -norequire, qw{ Sym::Type::_Ext Sym::Type };

    package Sym::Type::Opaque; # aka Fixed-Length Opaque
    use parent -norequire, qw{ Sym::Type::_Ext Sym::Type };

    package Sym::Variable;
    use parent -norequire, 'Sym';
    ::mk_accessor qw/ type value /;

    package Context;

    sub new {
        my ($class) = @_;

        bless {
            symbols  => {},
            macros   => {},
            programs => [],
        }, $class;
    }

    sub symbol {
        my ($self, $ident) = @_;
        my $sym = $self->symbols->{$ident} ||= Sym->new;
        $sym->ident($ident);
        # TODO: more better way?
        # In XDR Syntax specification, defining struct/enum/union will automatically
        # create alias having symbol which excludes its prefix type specifier.
        # e.g:
        #      struct foo { int bar; }; will convert to:
        #      struct foo { int bar; }; typedef struct foo foo;
        if ($ident =~ s/^(?:struct|enum|union)\s+//) {
            $self->symbol($ident)->bless('Type')->alias($sym);
        }
        $sym;
    }

    sub symbols { (shift)->{symbols} }

    sub add_prog {
        my ($self, $name) = @_;

        push @{ $self->{programs} }, $name;
    }

    sub macro {
        my ($self, $name, $def) = @_;

        if (defined $def) {
            $self->{macros}{$name} = $def;
        } else {
            $self->{macros}{$name}->();
        }
    }

    sub say {
        my $self = shift;
        push @{ $self->{buffer} }, join '', ' 'x$self->{indent}, @_;
    }

    sub sayf {
        my ($self, $fmt, @args) = @_;
        $self->say(sprintf $fmt, @args);
    }

    sub writeheader {
        my ($self, $name, $block) = @_;

        $self->{headers} ||= [];

        local $self->{indent} = 0;
        local $self->{buffer} = [];
        $self->say("/* This file was automatically generated by $0. *DO NOT MODIFY* this file directly. */");
        my $ucname = uc $name;
        $self->say("#ifndef _$ucname\_H_");
        $self->say("#define _$ucname\_H_");
        $block->();
        $self->say("#endif /* _$ucname\_H_ */");
        push @{ $self->{headers} }, [ $name, delete $self->{buffer} ];
    }

    sub writedef {
        my ($self, %args) = @_;

        my $realbuf = $self->{buffer};
        local $self->{buffer} = [];
        $self->sayf("$args{format} = {", $args{symbol});
        {
            local $self->{indent} = $self->{indent} + 4;
            $args{render}->();
        }
        $self->say('};');

        $self->{refindex} ||= {};
        my $stash = $self->{refindex}{ $args{symbol} } ||= { refcnt => 0 };
        $stash->{content} = join("\n", @{ $self->{buffer} });
        $stash->{refcnt} = $args{refcnt} if defined $args{refcnt};
        push @$realbuf, $stash;
    }

    sub refinc {
        my ($self, $symbol) = @_;

        # TODO: very ugly, need to fix this
        (my $sym = $symbol) =~ s/^&//;

        ($self->{refindex}{$sym} ||= { refcnt => 0 })->{refcnt}++;
        $symbol;
    }

    sub finalize {
        my ($self) = @_;

        for my $header (@{ $self->{headers} || [] }) {
            my ($name, $contents) = @$header;
            my $file = File::Spec->catfile(
                $ENV{HOME}, qw/ libvirt-wireshark-dissector src libvirt /, "$name.h");
            open my $fh, '>', $file
                or die "Cannot open file $file: $!";
            # use Data::Dumper;
            # warn Dumper $contents if $name eq 'libvirt_protocol_remote';
            # warn Dumper $self->{refindex} if $name eq 'libvirt_protocol_remote';
            print $fh join "\n", map { ref($_) ? $_->{content} : $_ } grep { ref($_) ? $_->{refcnt} : 1 } @$contents;
            print $fh "\n";
            close $fh;
        }
    }
}

my @xdr_base_types = qw{ int uint bool hyper uhyper float double quadruple char uchar short ushort };

my $context = Context->new;
local $Lexicalizer::c = $context;

for my $l (@xdr_base_types) {
    $context->macro($l => sub { sprintf 'XDR_%s, NULL, 0 /* %s */', uc($l), $l });
}

for my $proto (@ARGV) {
    # XXX: damn heuristic operation
    my ($name) = $proto =~ m{([^/]+?)_?protocol\.x$};
    $name =~ s/^vir//;
    $context->add_prog($name);

    my $source = do {
        open my $fh, '<', $proto
            or die "Cannot open $proto: $!";
        local $/ = undef;
        my $source = <$fh>;
        close $fh;
        $source;
    };

    # Remove uninteresting things
    $source =~ s{/\*.*?\*/}{}gs; # Comments
    $source =~ s{//.*$}{}gm;     # Comments C++ style
    $source =~ s{^\s*%.*$}{}gm;  # PP directives

    my @lexs = Lexicalizer::lexicalize($source);
# use Data::Dumper;
# warn Dumper \@lexs;

    $context->writeheader($name, sub {
        for my $lex (@lexs) {
            next if $lex->ident eq "enum $name\_procedure";

            if ($lex->isa('Sym::Variable')) {
                # sayf "static const int %s = %s;", $lex->ident, $lex->value;
                $context->sayf("#define %s (%s)", $lex->ident, $lex->value);
            } elsif ($lex->isa('Sym::Type')) {
                print_xdr_def($lex);
            } else {
                die "Unkown lexical appeared: $lex";
            }
        }

        my $procs = $context->symbol("enum $name\_procedure")
            or die "Cannot find procedures enumeration: enum $name\_procedure";
        # Procedure numbers are expected to be containing gaps, but needed to be sorted in ascending order.
        my @procedures = sort { $a->value <=> $b->value } @{ $procs->members };
        my $symbols = $context->symbols;
        $context->writedef(
            format => 'static const vir_proc_payload_t %s[]',
            symbol => "$name\_payload_def",
            refcnt => 1,
            render => sub {
                for my $proc (@procedures) {
                    $context->sayf('{ %d, %s, %s, %s },', $proc->value, map {
                        my $ident = lc($proc->ident)."_$_";
                        $ident =~ s/^$name\_proc/$name/;
                        $context->refinc($symbols->{$ident} ? "struct_$ident\_members_def" : 'NULL');
                    } qw{ args ret msg });
                }
            },
        );
        $context->writedef(
            format => 'static const value_string %s[]',
            symbol => "$name\_procedure_strings",
            refcnt => 1,
            render => sub {
                for my $proc (@procedures) {
                    my $ident = $proc->ident;
                    $ident =~ s/^$name\_proc_//i;
                    $context->sayf('{ %d, "%s" },', $proc->value, $ident);
                }
                $context->say('{ 0, NULL }');
            },
        );
    }); # /writeheader($name)
}

$context->writeheader('protocol' => sub {
    for my $type (@xdr_base_types) {
        $context->writedef(
            format => 'static const vir_xdrdef_t %s',
            symbol => "$type\_def",
            render => sub {
                $context->sayf('XDR_%s, NULL, 0', uc($type));
            },
        );
    }

    for my $prog (@{ $context->{programs} }) {
        $context->sayf('#include "libvirt/%s.h"', $prog);
    }

    $context->say('#define VIR_PROCEDURES_HEADERSET \\');
    $context->say(join "\\\n", map { split /\n/, sprintf <<'EOS', ($_)x2 } @{ $context->{programs} });
        { &hf_%s_procedure,
          { "procedure", "libvirt.procedure",
            FT_INT32, BASE_DEC,
            VALS(%s_procedure_strings), 0x0,
            NULL, HFILL}
        },
EOS

    $context->writedef(
        format => "static const value_string %s[]",
        symbol => 'program_strings',
        refcnt => 1,
        render => sub {
            $context->sayf('{ %s, "%s" },', $context->symbol(uc($_).'_PROGRAM')->value, uc($_))
                for @{ $context->{programs} };
            $context->say('{ 0, NULL }');
        },
    );

    $context->sayf('static int hf_%s_procedure = -1;', $_) for @{ $context->{programs} };

    $context->say(do {
        my $s = "#define VIR_PROG_SWITCH(prog)\n";
        $s .= "switch (prog) {\n";
        $s .= sprintf <<'EOS', uc($_), $_ for @{ $context->{programs} };
case %s_PROGRAM:
    VIR_PROG_CASE(%s);
    break;
EOS
        $s .= "}\n";
        join "\\\n", split /\n/, $s;
    });

    # $context->writedef(
    #     format => 'static const gintptr %s[][VIR_PDIC_LAST]',
    #     symbol => 'program_valindex',
    #     refcnt => 1,
    #     render => sub {
    #         $context->sayf("{ %s_PROGRAM, (gintptr)%s_procedure_strings, (gintptr)&hf_%s_procedure, (gintptr)%s_payload_def, sizeof(%s_payload_def) / sizeof(*%s_payload_def) },",
    #                        uc($_), ($_)x5) for @{ $context->{programs} };
    #     },
    # );
});

$context->finalize;

sub render_members_def {
    my ($symbol, $format, @members) = @_;

    $context->writedef(
        format => 'static vir_named_xdrdef_t %s[]',
        symbol => "$symbol\_def",
        render => sub {
            $context->sayf('{ ' . $format . ' },', @$_) for @members;
            $context->say('VIR_NAMED_XDRDEF_NULL');
        },
    );
}

sub print_xdr_def {
    my ($lex, $ident) = @_;
    $ident ||= $lex->ident;
    # remote_nonnull_domain is more readable than struct_remote_nonnull_domain
    $ident =~ s/^(?:struct|enum|union)\s+//;

    my $define_anon_subtypes = sub {
        my $i = 0;
        for my $anon (@_) {
            if (!defined $anon->ident) {
                $anon->ident(sprintf "$ident\_ANON_%d", $i++);
                print_xdr_def($anon, $anon->ident);
            }
        }
    };

    # $context->sayf('/* %s */', ref($lex));
    if ($lex->isa('Sym::Type::_Ref')) {
        $define_anon_subtypes->($lex->reftype);
    }
    if ($lex->isa('Sym::Type::Struct')) {
        $define_anon_subtypes->(map { $_->type } @{ $lex->members });

        render_members_def $lex->subdef, "\"%s\", %s" => map {
            # $_->type->ident is already filled by anon names
            [ $_->ident, $context->macro($_->type->ident) ];
        } @{ $lex->members };

        # return if $ident =~ /(?:_args|_ret)$/; # args/ret structs are never refered from others
    }
    if ($lex->isa('Sym::Type::Enum')) {
        render_members_def $lex->subdef, "\"%s\", XDR_INT, 0, %s" => map {
            [ $_->ident, $_->value ];
        } @{ $lex->members };
    }
    if ($lex->isa('Sym::Type::Union')) {
        $define_anon_subtypes->(map { $_->[1]->type } @{ $lex->case_specs });

        my $xdr_func = lc($lex->decl->type->xdr_type);
        $xdr_func =~ s/^u/u_/;

        # XXX: heuristic shit
        my $ctype = $lex->decl->type->ident;
        $ctype =~ s/^u/unsigned /;
        my $branchdef = $lex->subdef.'_branch_values_def';
        $context->writedef(
            format => "static const $ctype %s[]",
            symbol => $branchdef,
            render => sub {
                $context->say("$_,") for map { @{ $_->[0] } } @{ $lex->case_specs };
            },
        );
        my $i = 0;
        render_members_def $lex->subdef, "\"%s\", XDR_%s, %s, %s",
            [ $lex->decl->ident, $lex->decl->type->xdr_type,
              'xdr_'.$xdr_func, 'sizeof('.$ctype.')' ], map {
                my ($cases, $decl) = @$_;
                map {
                    [ $decl->ident, $lex->decl->type->xdr_type,
                      $context->refinc('&'.lc($decl->type->ident).'_def'),
                      '(uintptr_t)'.$context->refinc($branchdef).'+'.$i++ ];
                } @$cases;
            } @{ $lex->case_specs };
    }

    if ($lex->isa('Sym::Type')) {
        my $subdef = $lex->subdef;
        $subdef = $subdef ? "$subdef\_def" : '0';
        my $metainfo = $lex->metainfo // '0';

        $context->macro($ident => sub {
            sprintf 'XDR_%s, %s, %s /* %s */', $lex->xdr_type,
                $context->refinc($subdef), $context->refinc($metainfo), $ident;
        });
        # printf "#define VIR_%s_DEF XDR_%s, %s, %s\n",
        #     uc($ident), $type->xdr_type, $subdef, $metainfo;
        $context->writedef(
            format => 'static vir_xdrdef_t %s',
            symbol => "$ident\_def",
            render => sub {
                $context->say($context->macro($ident));
            },
        );
    } else {
        die "Unkown type appeared: $lex";
    }
}

package Lexicalizer;
use Carp;

our $c;

sub rxmatch {
    my ($rx) = @_;
    # print STDERR "rxmatch( $rx ) = ";
    unless (s/^\s*(?:$rx)//s) {
        # print STDERR "UNMATCH\n";
        confess "LEX_UNMATCH $rx";
    }
    my $s = $&;
    $s =~ s/^\s*//;
    # print STDERR "$s\n";
    $s;
}

sub lexor {
    my @errors;
    my $snapshot = $_;
    while (my $handler = shift) {
        my $ret = eval { $handler->() };
        if (defined $ret) {
            return $ret;
        }
        push @errors, $@;
        $_ = $snapshot;
    }
    die join "\n", map { "[$_]\n$errors[$_]" } (0..$#errors);
}

sub decimal_constant {
    rxmatch '\-?[0-9]+';
}

sub hexadecimal_constant {
    rxmatch '\-?0x[0-9A-Fa-f]+';
}

sub octal_constant {
    rxmatch '\-?0[0-9]+';
}

sub constant {
    lexor \&hexadecimal_constant, \&octal_constant, \&decimal_constant;
}

sub identifier {
    rxmatch '[_a-zA-Z][_a-zA-Z0-9]*';
}

sub value {
    lexor \&constant, \&identifier;
}

sub enum_type_spec {
    rxmatch 'enum';
    my $body = lexor \&enum_body, \&identifier;
    if (ref $body eq 'ARRAY') {
        Sym::Type::Enum->new(members => $body);
    } else {
        $c->symbol("enum $body")->bless('Type::Enum');
    }
}

sub enum_body {
    rxmatch '{';
    my @members;
    do {
        my $ident = identifier();
        rxmatch '=';
        my $value = value();
        push @members, $c->symbol($ident)->bless('Variable')->value($value);
    } while rxmatch('}|,') eq ',';
    \@members;
}

sub struct_type_spec {
    rxmatch 'struct';
    my $body = lexor \&struct_body, \&identifier;
    if (ref $body eq 'ARRAY') {
        Sym::Type::Struct->new(members => $body);
    } else {
        $c->symbol("struct $body")->bless('Type::Struct');
    }
}

sub struct_body {
    rxmatch '{';
    local $c->{symbols} = { %{ $c->{symbols} } };
    my @members;
    while (my $decl = lexor \&declaration, sub { rxmatch('}') }) {
        last if $decl eq '}';
        rxmatch ';';
        push @members, $decl;
    }
    \@members;
}

sub case_spec {
    my @cases;
    while (my $case = eval { rxmatch 'case' }) {
        push @cases, value();
        rxmatch ':';
    }
    my $decl = declaration();
    rxmatch ';';
    [ \@cases, $decl ];
}

sub union_type_spec {
    rxmatch 'union';
    local $c->{symbols} = { %{ $c->{symbols} } };
    my $body = lexor \&union_body, \&identifier;
    if (ref $body eq 'ARRAY') {
        Sym::Type::Union->new(decl => $body->[0], case_specs => $body->[1]);
    } else {
        $c->symbol("union $body")->bless('Type::Union');
    }
}

sub union_body {
    rxmatch 'switch'; rxmatch '\(';
    my $decl = declaration();
    rxmatch '\)'; rxmatch '{';
    my @case_specs;
    while (my $spec = eval { case_spec() }) {
        push @case_specs, $spec;
    }
    # TODO: parse default
    rxmatch '}';
    [ $decl, \@case_specs ];
}

sub constant_def {
    rxmatch 'const';
    my $ident = identifier();
    rxmatch '=';
    my $value = lexor \&constant, \&identifier;
    rxmatch ';';

    $c->symbol($ident)->bless('Variable')->value($value);
}

sub type_def {
    my $ret = lexor sub {
        rxmatch 'typedef';
        my $var = declaration();
        my $type = $var->type;
        $var->bless('Type')->alias($type);
    }, sub {
        rxmatch 'enum';
        my $ident = identifier();
        my $body = enum_body();
        $c->symbol("enum $ident")->bless('Type::Enum')->members($body);
    }, sub {
        rxmatch 'struct';
        my $ident = identifier();
        my $body = struct_body();
        $c->symbol("struct $ident")->bless('Type::Struct')->members($body);
    }, sub {
        rxmatch 'union';
        my $ident = identifier();
        my $body = union_body();
        $c->symbol("union $ident")->bless('Type::Union')
            ->decl($body->[0])->case_specs($body->[1]);
    };
    rxmatch ';';
    $ret;
}

sub type_specifier {
    lexor sub {
        my $ts = rxmatch '(?:unsigned\s+)?(?:int|hyper|char|short)|float|double|quadruple|bool';
        $ts =~ s/^unsigned\s+/u/;
        $c->symbol($ts)->bless('Type');
    }, \&enum_type_spec, \&struct_type_spec, \&union_type_spec, sub {
        my $ident = identifier();
        $c->symbol($ident)->bless('Type');
    };
}

sub declaration {
    lexor sub {
        my $type = lexor sub {
            my $type = rxmatch 'opaque|string';
            my $klass = ucfirst $type;
            "Sym::Type::$klass"->new;
        }, \&type_specifier;
        my $ident = identifier();
        # I know that type 'string' does not accept '[]'(fixed length), but I don't care about that
        # TODO: some lazyness here
        if (my $ex = eval { rxmatch '<|\[' }) {
            my $value = eval { value() };
            die $@ if !$value && $ex ne '<'; # Length could be null if it is variable length

            rxmatch($ex eq '<' ? '>' : '\]');
            if (ref($type) eq 'Sym::Type') { # Expect Array or Vector
                my $vtype = ($ex eq '<') ? 'Array' : 'Vector';

                $type = "Sym::Type::$vtype"->new(length => $value, reftype => $type);
                # $type = $c->symbol($type->ident.$ex.($value||'').($ex eq '<' ? '>' : ']'))
                #     ->bless("Type::$vtype")->length($value)->reftype($type);
            } else {
                $type->length($value);
                $type->bless('Type::Bytes') if $type->isa('Sym::Type::Opaque') && $ex eq '<';
            }
        } elsif (ref($type) ne 'Sym::Type') { # Found String or Opaque but not followed by length specifier
            die $@;
        }

        $c->symbol($ident)->bless('Variable')->type($type);
    }, sub {
        my $type = type_specifier();
        rxmatch '\*';
        my $ident = identifier();

        $c->symbol($ident)->bless('Variable')->type(
            Sym::Type::Pointer->new(reftype => $type));
            # $c->symbol($type->ident.'*')->bless('Type::Pointer')->reftype($type));
    }, sub {
        rxmatch 'void';
        $c->symbol('void')->bless('Type');
    };
}

sub definition {
    lexor \&type_def, \&constant_def;
}

sub lexicalize {
    my ($source) = @_;

    my $nlines = @{[$source =~ /\n/g]};
    my @lexs;
    while ($source =~ /\S/s) {
        local $_ = $source;
        my $lex = definition();
        if (!$lex) {
            my $line = @{[/\n/g]};
            die sprintf "Syntax error at line %d, near %s:\n %s", $nlines - $line, substr($source, 0, 256), $@;
        }
        push @lexs, $lex;
        $source = $_;
    }
    @lexs;
}

