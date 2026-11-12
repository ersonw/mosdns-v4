package telegram_bot

// Minimal XLSX writer. The bot has to hand an administrator a spreadsheet, and
// pulling in a full Excel library would add a dependency tree to a DNS server
// for the sake of one export, so this writes the smallest valid workbook: one
// sheet, inline strings (no sharedStrings part), plain numbers for counts.
//
// A test unzips the result and checks the parts are well formed, because a
// corrupt xlsx would only surface as "Telegram rejected the document".

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

const (
	contentTypesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>`

	rootRelsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>`

	workbookRelsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>`
)

// writeXLSX builds a single-sheet workbook. cells holds the header row first,
// then one slice per data row; nil and empty strings become blank cells.
func writeXLSX(sheetName string, cells [][]interface{}) ([]byte, error) {
	if sheetName == "" {
		sheetName = "Sheet1"
	}
	// Excel limits a sheet name to 31 characters and forbids : \ / ? * [ ]
	r := strings.NewReplacer(":", "_", "\\", "_", "/", "_", "?", "_", "*", "_", "[", "_", "]", "_")
	sheetName = r.Replace(sheetName)
	if len(sheetName) > 31 {
		sheetName = sheetName[:31]
	}

	workbookXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="%s" sheetId="1" r:id="rId1"/></sheets>
</workbook>`, escapeXML(sheetName))

	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)
	parts := []struct {
		name string
		body string
	}{
		{"[Content_Types].xml", contentTypesXML},
		{"_rels/.rels", rootRelsXML},
		{"xl/workbook.xml", workbookXML},
		{"xl/_rels/workbook.xml.rels", workbookRelsXML},
		{"xl/worksheets/sheet1.xml", sheetXML(cells)},
	}
	for _, part := range parts {
		f, err := zw.Create(part.name)
		if err != nil {
			return nil, err
		}
		if _, err := io.WriteString(f, part.body); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func sheetXML(cells [][]interface{}) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	b.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`)
	for rowIdx, row := range cells {
		r := rowIdx + 1
		b.WriteString(fmt.Sprintf(`<row r="%d">`, r))
		for colIdx, value := range row {
			ref := columnName(colIdx+1) + fmt.Sprintf("%d", r)
			switch v := value.(type) {
			case nil:
				continue
			case int:
				b.WriteString(fmt.Sprintf(`<c r="%s"><v>%d</v></c>`, ref, v))
			case int64:
				b.WriteString(fmt.Sprintf(`<c r="%s"><v>%d</v></c>`, ref, v))
			default:
				text := fmt.Sprintf("%v", v)
				if text == "" {
					continue
				}
				b.WriteString(fmt.Sprintf(`<c r="%s" t="inlineStr"><is><t>%s</t></is></c>`, ref, escapeXML(text)))
			}
		}
		b.WriteString(`</row>`)
	}
	b.WriteString(`</sheetData></worksheet>`)
	return b.String()
}

// columnName turns 1 into "A", 27 into "AA".
func columnName(n int) string {
	name := ""
	for n > 0 {
		n--
		name = string(rune('A'+n%26)) + name
		n /= 26
	}
	return name
}

func escapeXML(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
