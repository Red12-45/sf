// routes/salesDownload.js
const express = require('express');
const ExcelJS = require('exceljs');

module.exports = function makeSalesDownloadRoutes({ db, isAuthenticated, restrictRoute }) {
  const router = express.Router();

  /* ─────────── DOWNLOAD SALES → EXCEL ─────────── */
  // GET /download-sales
  router.get(
    '/download-sales',
    isAuthenticated,
    restrictRoute('/sales'),
    async (req, res) => {
      try {
        const accountId = req.session.user.accountId;
        const { saleDate, month, status } = req.query;

        /* 1. build the same query logic used in /sales */
        let q = db.collection('sales')
                  .where('accountId', '==', accountId)
                  .orderBy('createdAt', 'desc');

        if (saleDate) {
          q = q.where('saleDate', '==', saleDate);
        } else if (month) {
          const [y, m] = month.split('-');
          const start  = `${month}-01`;
          let nextM    = parseInt(m, 10) + 1,
              nextY    = parseInt(y, 10);
          if (nextM > 12) { nextM = 1; nextY++; }
          const end = `${nextY}-${String(nextM).padStart(2, '0')}-01`;
          q = q.where('saleDate', '>=', start).where('saleDate', '<', end);
        }
        if (status && status.trim() && status !== 'All') {
          q = q.where('status', '==', status);
        }

        const snap  = await q.get();
        const sales = snap.docs.map(d => ({ id: d.id, ...d.data() }));

        /* 2. create the workbook */
        const wb = new ExcelJS.Workbook();
        const ws = wb.addWorksheet('Sales');

        ws.columns = [
          { header: 'Sale Date',       key: 'saleDate',        width: 12 },
          { header: 'Product',         key: 'productName',     width: 32 },
          { header: 'Wholesale ₹',     key: 'wholesalePrice',  width: 14 },
          { header: 'Retail ₹',        key: 'retailPrice',     width: 12 },
          { header: 'Quantity',        key: 'saleQuantity',    width: 10 },
          { header: 'Unit',            key: 'unit',            width: 8  },
          { header: 'Total Sale ₹',    key: 'totalSale',       width: 14 },
          { header: 'Profit / Unit ₹', key: 'profitPerUnit',   width: 16 },
          { header: 'Total Profit ₹',  key: 'profit',          width: 14 },
          { header: 'GST Payable ₹',   key: 'gstPayable',      width: 14 },
          { header: 'Status',          key: 'status',          width: 24 },
          { header: 'Extra Info',      key: 'extraInfo',       width: 32 },
          { header: 'Created At',      key: 'createdAt',       width: 22 }
        ];

        sales.forEach(s => ws.addRow({
          ...s,
          totalSale  : s.totalSale || (s.retailPrice * s.saleQuantity),
          gstPayable : s.gstPayable !== undefined ? s.gstPayable : '',
          createdAt  : (s.createdAt?.toDate ? s.createdAt.toDate()
                                            : new Date(s.createdAt))
                       .toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })
        }));

        /* 3. stream it to the client */
        res.setHeader(
          'Content-Type',
          'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        );
        res.setHeader(
          'Content-Disposition',
          `attachment; filename="sales_${Date.now()}.xlsx"`
        );

        await wb.xlsx.write(res);
        res.end();
      } catch (err) {
        res.status(500).send(err.toString());
      }
    }
  );

  return router;
};
