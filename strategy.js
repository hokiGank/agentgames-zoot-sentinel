// Agent Games — Steal the VFY strategy (deterministic, no LLM in the final call)
// Game: 100 VFY start, 20 turns. HOLD=0, FORTIFY costs 2 (blocks up to 6 incoming),
// EXTRACT N (max 10) steals from opponent; fortified opponent reduces gain by 6.

function decideAction(state, history = []) {
  const self = BigInt(state.selfBalance);
  const opp = BigInt(state.opponentBalance);
  const oppFortified = !!state.opponentFortifiedUntilTurn;
  const selfFortified = !!state.selfFortifiedUntilTurn;

  const lastOpp = history.length ? history[history.length - 1].opponentAction : null;

  // 1. Broke: cannot afford FORTIFY cost.
  if (self <= 2n) {
    // Fortify pointless if we can't pay; extract whatever we can.
    return oppFortified ? { type: 'HOLD' } : { type: 'EXTRACT', amount: Math.min(10, Number(opp)) };
  }

  // 2. Opponent fortified this turn -> EXTRACT is halved to N-6; grab cheap max.
  if (oppFortified) {
    // still worth extracting small: gain = max(0, N-6); only if N>6
    return { type: 'EXTRACT', amount: 10 };
  }

  // 3. Expect extraction: opponent extracted last turn or is ahead and aggressive.
  const oppAggressive = lastOpp === 'EXTRACT' || opp > self;
  if (oppAggressive && !selfFortified) {
    // Fortify (blocks 6) and they extract max 10 -> we lose only 4 vs 10. Cost 2.
    return { type: 'FORTIFY' };
  }

  // 4. Default: press the advantage.
  return { type: 'EXTRACT', amount: Math.min(10, Number(opp)) };
}

module.exports = { decideAction };
