use simplex::fuzz::FuzzProgramTrait;
use simplex::program::{Program, ProgramSchema};
use simplex::simplicityhl::Arguments;

use super::unit::{self, Expect, Signatures, UnitTx};

/// One call into a program: a test program that picks the function under test by
/// `FUNCTION_INDEX`, or a contract spent along one of its paths.
pub trait DispatchCase: Sized + 'static {
    type Program: FuzzProgramTrait;

    const PROGRAM_NAME: &'static str = "program";

    fn arguments() -> <Self::Program as ProgramSchema>::Arguments;

    fn into_witness(self) -> <Self::Program as ProgramSchema>::Witness;

    /// The unit transaction the case runs in.
    fn unit_tx(&self) -> UnitTx {
        UnitTx::default()
    }

    fn program() -> Program {
        let arguments: Arguments = Self::arguments().into();

        Self::Program::build_program(&arguments)
            .unwrap_or_else(|error| panic!("{} does not compile: {error}", Self::PROGRAM_NAME))
    }

    #[track_caller]
    fn accepts(self) {
        self.check(Signatures::Checked, Expect::Ok);
    }

    #[track_caller]
    fn rejects(self, reason: Expect) {
        assert_ne!(
            reason,
            Expect::Ok,
            "use `accepts` for cases that must succeed"
        );

        self.check(Signatures::Checked, reason);
    }

    /// As [`DispatchCase::accepts`], with every signature check passing.
    #[track_caller]
    fn accepts_unsigned(self) {
        self.check(Signatures::Skipped, Expect::Ok);
    }

    /// As [`DispatchCase::rejects`], with every signature check passing, so the
    /// rejection comes from something other than the signature.
    #[track_caller]
    fn rejects_unsigned(self, reason: Expect) {
        assert_ne!(
            reason,
            Expect::Ok,
            "use `accepts_unsigned` for cases that must succeed"
        );

        self.check(Signatures::Skipped, reason);
    }

    #[track_caller]
    fn check(self, signatures: Signatures, expect: Expect) {
        let tx = self.unit_tx();

        unit::check_in(
            &Self::program(),
            self.into_witness(),
            signatures,
            tx,
            expect,
        );
    }
}
