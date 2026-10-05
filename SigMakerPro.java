//Signature maker for Ghidra, inspired by A200K/IDA-Pro-SigMaker.
//Generates a unique signature from the cursor (or from the current selection) and prints it as IDA, Cheat Engine / x64Dbg and Pattern + Mask.
//@author SigMaker
//@category Signatures
//@keybinding ctrl alt S
//@menupath Tools.SigMaker.Create Signature

import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class SigMaker extends GhidraScript {

	// ------------------------------------------------------------------
	// Configuration
	// ------------------------------------------------------------------

	/** Maximum signature length in bytes before giving up. */
	private static final int MAX_SIG_BYTES = 200;

	/** Max number of candidate matches tracked while the pattern is still short. */
	private static final int MAX_CANDIDATES = 50000;

	/** true = wildcard every operand byte (immediates, displacements, addresses). */
	private static final boolean WILDCARD_ALL_OPERANDS = false;

	/** If no unique signature exists at the cursor, try signatures of the xrefs to it. */
	private static final boolean TRY_XREFS = true;
	private static final int MAX_XREFS_TRIED = 30;
	private static final int MAX_XREFS_SHOWN = 5;

	/** What goes to the clipboard: "IDA", "CE", "MASK" or "ALL". */
	private static final String CLIPBOARD = "CE";

	// ------------------------------------------------------------------
	// Data holders
	// ------------------------------------------------------------------

	/** One instruction (or one raw byte for non-code). mask: 0xFF = fixed, 0x00 = wildcard. */
	private static class Unit {
		byte[] bytes;
		byte[] mask;
		Address next;
	}

	private static class Sig {
		byte[] bytes;
		byte[] mask;
		Address start;
		int matches;
	}

	// ------------------------------------------------------------------
	// Entry point
	// ------------------------------------------------------------------

	@Override
	public void run() throws Exception {
		if (currentProgram == null) {
			printerr("SigMaker: no program open.");
			return;
		}

		// Selection mode: signature of exactly the selected bytes
		if (currentSelection != null && !currentSelection.isEmpty()) {
			Sig s = fromSelection();
			if (s == null) {
				printerr("SigMaker: could not read the selected bytes.");
				return;
			}
			report("Selection", s, s.start);
			copyToClipboard(s);
			return;
		}

		Address a = (currentLocation != null) ? currentLocation.getAddress() : currentAddress;
		if (a == null) {
			printerr("SigMaker: no cursor address.");
			return;
		}
		CodeUnit cu = currentProgram.getListing().getCodeUnitContaining(a);
		if (cu != null) {
			a = cu.getMinAddress();
		}

		Sig s = generate(a);
		if (s != null) {
			report("Unique signature", s, a);
			copyToClipboard(s);
			return;
		}

		printerr("SigMaker: no unique signature found at " + a +
			" (limit " + MAX_SIG_BYTES + " bytes).");

		if (!TRY_XREFS) {
			return;
		}

		println("SigMaker: trying XREF signatures...");
		List<Sig> found = new ArrayList<>();
		ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(a);
		int tried = 0;
		while (it.hasNext() && tried < MAX_XREFS_TRIED) {
			monitor.checkCancelled();
			Reference r = it.next();
			Address from = r.getFromAddress();
			if (!from.isMemoryAddress() ||
				currentProgram.getListing().getInstructionAt(from) == null) {
				continue;
			}
			tried++;
			Sig xs = generate(from);
			if (xs != null) {
				found.add(xs);
			}
		}

		if (found.isEmpty()) {
			printerr("SigMaker: no unique XREF signature either.");
			return;
		}

		found.sort((x, y) -> Integer.compare(x.bytes.length, y.bytes.length));
		int shown = Math.min(found.size(), MAX_XREFS_SHOWN);
		for (int i = 0; i < shown; i++) {
			Sig xs = found.get(i);
			report("XREF signature #" + (i + 1) + " (instruction that references " + a + ")",
				xs, xs.start);
		}
		copyToClipboard(found.get(0));
	}

	// ------------------------------------------------------------------
	// Signature generation
	// ------------------------------------------------------------------

	/** Extends the pattern instruction by instruction until it matches exactly once. */
	private Sig generate(Address start) throws Exception {
		ByteArrayOutputStream pb = new ByteArrayOutputStream();
		ByteArrayOutputStream mb = new ByteArrayOutputStream();
		List<Address> cands = null;
		Address cur = start;
		boolean unique = false;

		while (cur != null && pb.size() < MAX_SIG_BYTES) {
			monitor.checkCancelled();
			Unit u = buildUnit(cur);
			if (u == null) {
				break;
			}
			int prevLen = pb.size();
			pb.write(u.bytes, 0, u.bytes.length);
			mb.write(u.mask, 0, u.mask.length);

			if (cands == null) {
				cands = findAll(pb.toByteArray(), mb.toByteArray(), MAX_CANDIDATES);
			}
			else {
				cands = filter(cands, u, prevLen);
			}

			if (cands != null) {
				if (cands.size() == 1 && cands.get(0).equals(start)) {
					unique = true;
					break;
				}
				if (cands.isEmpty()) {
					break;
				}
			}
			cur = u.next;
		}

		if (!unique) {
			return null;
		}
		return finish(start, pb, mb);
	}

	private Sig fromSelection() throws Exception {
		Address min = currentSelection.getMinAddress();
		Address max = currentSelection.getMaxAddress();
		ByteArrayOutputStream pb = new ByteArrayOutputStream();
		ByteArrayOutputStream mb = new ByteArrayOutputStream();
		Address cur = min;
		while (cur != null && cur.compareTo(max) <= 0) {
			monitor.checkCancelled();
			Unit u = buildUnit(cur);
			if (u == null) {
				break;
			}
			pb.write(u.bytes, 0, u.bytes.length);
			mb.write(u.mask, 0, u.mask.length);
			cur = u.next;
		}
		if (pb.size() == 0) {
			return null;
		}
		return finish(min, pb, mb);
	}

	/** Trims trailing wildcards and counts how many times the final pattern matches. */
	private Sig finish(Address start, ByteArrayOutputStream pb, ByteArrayOutputStream mb)
			throws Exception {
		byte[] b = pb.toByteArray();
		byte[] m = mb.toByteArray();
		int n = m.length;
		while (n > 0 && m[n - 1] == 0) {
			n--;
		}
		Sig s = new Sig();
		s.bytes = Arrays.copyOf(b, n);
		s.mask = Arrays.copyOf(m, n);
		s.start = start;
		if (n > 0) {
			List<Address> all = findAll(s.bytes, s.mask, 1000);
			s.matches = (all == null) ? 1001 : all.size();
		}
		return s;
	}

	/** Builds bytes + mask for the instruction at a (or a single raw byte if not code). */
	private Unit buildUnit(Address a) {
		Memory mem = currentProgram.getMemory();
		Instruction ins = currentProgram.getListing().getInstructionAt(a);
		Unit u = new Unit();
		try {
			if (ins == null) {
				byte[] raw = new byte[1];
				mem.getBytes(a, raw);
				u.bytes = raw;
				u.mask = new byte[] { (byte) 0xFF };
				u.next = a.next();
				return u;
			}

			byte[] b = ins.getBytes();
			byte[] m = new byte[b.length];
			Arrays.fill(m, (byte) 0xFF);

			InstructionPrototype proto = ins.getPrototype();
			for (int op = 0; op < ins.getNumOperands(); op++) {
				byte[] om;
				try {
					om = proto.getOperandValueMask(op).getBytes();
				}
				catch (Exception e) {
					continue;
				}
				int type = ins.getOperandType(op);
				boolean hasRef = ins.getOperandReferences(op).length > 0;
				boolean addrLike =
					(type & (OperandType.ADDRESS | OperandType.RELATIVE)) != 0 || hasRef;
				boolean dynamic = (type & OperandType.DYNAMIC) != 0;

				int n = Math.min(om.length, b.length);
				int i = 0;
				while (i < n) {
					// only bytes that belong ENTIRELY to the operand are candidates
					// (keeps ModRM/SIB/opcode bytes that merely contain register bits)
					if ((om[i] & 0xFF) != 0xFF) {
						i++;
						continue;
					}
					int j = i;
					while (j < n && (om[j] & 0xFF) == 0xFF) {
						j++;
					}
					int run = j - i;
					if (WILDCARD_ALL_OPERANDS || addrLike || (dynamic && run >= 4)) {
						for (int k = i; k < j; k++) {
							m[k] = 0;
						}
					}
					i = j;
				}
			}
			for (int k = 0; k < b.length; k++) {
				if (m[k] == 0) {
					b[k] = 0;
				}
			}
			u.bytes = b;
			u.mask = m;
			u.next = ins.getMaxAddress().next();
			return u;
		}
		catch (Exception e) {
			return null;
		}
	}

	// ------------------------------------------------------------------
	// Searching
	// ------------------------------------------------------------------

	/** All matches of bytes/mask in program memory. Returns null if more than cap. */
	private List<Address> findAll(byte[] bytes, byte[] mask, int cap) throws Exception {
		Memory mem = currentProgram.getMemory();
		List<Address> out = new ArrayList<>();
		Address a = mem.getMinAddress();
		while (a != null) {
			monitor.checkCancelled();
			Address f = mem.findBytes(a, bytes, mask, true, monitor);
			if (f == null) {
				break;
			}
			out.add(f);
			if (out.size() > cap) {
				return null;
			}
			a = f.next();
		}
		return out;
	}

	/** Keeps only the candidates whose bytes at +offset also match the new unit. */
	private List<Address> filter(List<Address> cands, Unit u, int offset) {
		Memory mem = currentProgram.getMemory();
		List<Address> out = new ArrayList<>();
		byte[] buf = new byte[u.bytes.length];
		for (Address c : cands) {
			try {
				Address t = c.addNoWrap(offset);
				if (mem.getBytes(t, buf) != buf.length) {
					continue;
				}
				boolean ok = true;
				for (int i = 0; i < buf.length; i++) {
					if (((buf[i] ^ u.bytes[i]) & u.mask[i]) != 0) {
						ok = false;
						break;
					}
				}
				if (ok) {
					out.add(c);
				}
			}
			catch (Exception e) {
				// unreadable / out of range: drop candidate
			}
		}
		return out;
	}

	// ------------------------------------------------------------------
	// Formatting / output
	// ------------------------------------------------------------------

	private static boolean wild(Sig s, int i) {
		return s.mask[i] == 0;
	}

	private static String hex(byte b) {
		return String.format("%02X", b & 0xFF);
	}

	/** IDA style: 48 8B 05 ? ? ? ? */
	private String fmtIDA(Sig s) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < s.bytes.length; i++) {
			if (i > 0) {
				sb.append(' ');
			}
			sb.append(wild(s, i) ? "?" : hex(s.bytes[i]));
		}
		return sb.toString();
	}

	/** Cheat Engine / x64Dbg style: 48 8B 05 ?? ?? ?? ?? */
	private String fmtCE(Sig s) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < s.bytes.length; i++) {
			if (i > 0) {
				sb.append(' ');
			}
			sb.append(wild(s, i) ? "??" : hex(s.bytes[i]));
		}
		return sb.toString();
	}

	/** Pattern: \x48\x8B\x05\x00\x00\x00\x00 */
	private String fmtPattern(Sig s) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < s.bytes.length; i++) {
			sb.append("\\x").append(wild(s, i) ? "00" : hex(s.bytes[i]));
		}
		return sb.toString();
	}

	/** Mask: xxx???? */
	private String fmtMask(Sig s) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < s.bytes.length; i++) {
			sb.append(wild(s, i) ? '?' : 'x');
		}
		return sb.toString();
	}

	/** C array: { 0x48, 0x8B, 0x05, 0x00 } */
	private String fmtCArray(Sig s) {
		StringBuilder sb = new StringBuilder("{ ");
		for (int i = 0; i < s.bytes.length; i++) {
			if (i > 0) {
				sb.append(", ");
			}
			sb.append("0x").append(wild(s, i) ? "00" : hex(s.bytes[i]));
		}
		return sb.append(" }").toString();
	}

	private void report(String title, Sig s, Address at) {
		Function f = currentProgram.getFunctionManager().getFunctionContaining(at);
		long rva = at.subtract(currentProgram.getImageBase());

		println("");
		println("==================== SigMaker ====================");
		println(title);
		println("Address  : " + at + "  (RVA 0x" + Long.toHexString(rva).toUpperCase() + ")" +
			(f != null ? "  in " + f.getName() : ""));
		println("Length   : " + s.bytes.length + " bytes");
		println("Matches  : " + (s.matches > 1000 ? ">1000" : String.valueOf(s.matches)) +
			(s.matches == 1 ? "  (unique)" : "  (NOT unique)"));
		println("--------------------------------------------------");
		println("IDA              : " + fmtIDA(s));
		println("Cheat Engine/x64 : " + fmtCE(s));
		println("Pattern          : \"" + fmtPattern(s) + "\"");
		println("Mask             : \"" + fmtMask(s) + "\"");
		println("C array          : " + fmtCArray(s));
		println("==================================================");
	}

	private void copyToClipboard(Sig s) {
		String text;
		switch (CLIPBOARD) {
			case "IDA":
				text = fmtIDA(s);
				break;
			case "MASK":
				text = fmtPattern(s) + " " + fmtMask(s);
				break;
			case "ALL":
				text = "IDA: " + fmtIDA(s) + "\nCE: " + fmtCE(s) + "\nPattern: " + fmtPattern(s) +
					"\nMask: " + fmtMask(s);
				break;
			default:
				text = fmtCE(s);
		}
		try {
			Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
				new StringSelection(text), null);
			println("Copied to clipboard (" + CLIPBOARD + ").");
		}
		catch (Throwable t) {
			println("Clipboard not available: " + t.getMessage());
		}
	}
}
