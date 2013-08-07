/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "docio.h"

void docio_init(struct docio_handle *handle, struct filemgr *file)
{
    handle->file = file;
    handle->curblock = BLK_NOT_FOUND;
    handle->curpos = 0;
	handle->lastbid = BLK_NOT_FOUND;
	handle->readbuffer = (void *)mempool_alloc(file->blocksize);
}

void docio_free(struct docio_handle *handle)
{
	mempool_free(handle->readbuffer);
}

INLINE bid_t docio_append_doc_raw(struct docio_handle *handle, uint64_t size, void *buf)
{
	bid_t bid;
	uint32_t offset;
	
	if (handle->curblock == BLK_NOT_FOUND) {
		// allocate new block
		handle->curblock = filemgr_alloc(handle->file);
		handle->curpos = 0;
	}
	if (!filemgr_is_writable(handle->file, handle->curblock)) {
		// allocate new block
		handle->curblock = filemgr_alloc(handle->file);
		handle->curpos = 0;
	}

	if (size <= handle->file->blocksize - handle->curpos) {
		// simply append to current block
		offset = handle->curpos;
		filemgr_write_offset(handle->file, handle->curblock, offset, size, buf);

		handle->curpos += size;

		return handle->curblock * handle->file->blocksize + offset;
		
	}else{
		// not simply fitted into current block
		bid_t begin, end, i, startpos;
		uint32_t nblock = size / handle->file->blocksize;
		uint32_t remain = size % handle->file->blocksize;
		uint64_t remainsize = size;

	#ifdef DOCIO_BLOCK_ALIGN
		if (remain <= handle->file->blocksize - handle->curpos && 
			filemgr_get_next_alloc_block(handle->file) == handle->curblock+1) {

			// start from current block
			filemgr_alloc_multiple(handle->file, nblock, &begin, &end);
			assert(begin == handle->curblock + 1);
			
			offset = handle->file->blocksize - handle->curpos;
			if (offset > 0) 
				filemgr_write_offset(handle->file, handle->curblock, handle->curpos, offset, buf);
			remainsize -= offset;

			startpos = handle->curblock * handle->file->blocksize + handle->curpos;			
		}else {
			// allocate new multiple blocks
			filemgr_alloc_multiple(handle->file, nblock+((remain>0)?1:0), &begin, &end);
			offset = 0;

			startpos = begin * handle->file->blocksize;
		}

	#else
		// simple append mode .. always append at the end of file
		if (filemgr_get_next_alloc_block(handle->file) == handle->curblock+1) {
			// start from current block
			offset = handle->file->blocksize - handle->curpos;
			filemgr_alloc_multiple(handle->file, nblock + ((remain>offset)?1:0), &begin, &end);
			assert(begin == handle->curblock + 1);
			
			if (offset > 0) 
				filemgr_write_offset(handle->file, handle->curblock, handle->curpos, offset, buf);
			remainsize -= offset;

			startpos = handle->curblock * handle->file->blocksize + handle->curpos;			
		}else {
			// allocate new multiple blocks
			filemgr_alloc_multiple(handle->file, nblock+((remain>0)?1:0), &begin, &end);
			offset = 0;

			startpos = begin * handle->file->blocksize;
		}

	#endif

		for (i=begin; i<=end; ++i) {
			handle->curblock = i;
			if (remainsize >= handle->file->blocksize) {
				// write entire block
				filemgr_write(handle->file, i, buf + offset);
				offset += handle->file->blocksize;
				remainsize -= handle->file->blocksize;
				handle->curpos = handle->file->blocksize;
				
			}else{
				// write rest of document
				assert(i==end);
				filemgr_write_offset(handle->file, i, 0, remainsize, buf + offset);
				offset += remainsize;
				handle->curpos = remainsize;
			}
		}

		return startpos;
	}

	return 0;
}

typedef enum {
	DOCIO_SIMPLY_APPEND,
	DOCIO_CHECK_ALIGN
} _docio_append_mode_t;

INLINE bid_t _docio_append_doc_component(struct docio_handle *handle, void *buf, 
		uint64_t size, uint64_t docsize, _docio_append_mode_t mode)
{
	bid_t bid;
	uint64_t offset;
	uint64_t basis_size;

	if (handle->curblock == BLK_NOT_FOUND) {
		// allocate new block
		handle->curblock = filemgr_alloc(handle->file);
		handle->curpos = 0;
	}
	if (!filemgr_is_writable(handle->file, handle->curblock)) {
		// allocate new block
		handle->curblock = filemgr_alloc(handle->file);
		handle->curpos = 0;
	}
	
	if (mode == DOCIO_CHECK_ALIGN) {
		// block aligning mode
		basis_size = docsize;
	}else{
		basis_size = size;
	}
	
	if (basis_size <= handle->file->blocksize - handle->curpos) {
		// simply append to current block
		offset = handle->curpos;
		filemgr_write_offset(handle->file, handle->curblock, offset, size, buf);

		handle->curpos += size;

		return handle->curblock * handle->file->blocksize + offset;
		
	}else{
		// not simply fitted into current block
		bid_t begin, end, i, startpos;
		uint32_t nblock = basis_size / handle->file->blocksize;
		uint32_t remain = basis_size % handle->file->blocksize;
		uint64_t remainsize = size;

		if ((remain <= handle->file->blocksize - handle->curpos && 
			filemgr_get_next_alloc_block(handle->file) == handle->curblock+1) || 
			mode == DOCIO_SIMPLY_APPEND) {
			// start from current block
			if (mode == DOCIO_CHECK_ALIGN) {
				// allocate next blocks
				filemgr_alloc_multiple(handle->file, nblock, &begin, &end);
				assert(begin == handle->curblock + 1);
			}else{
				begin = handle->curblock + 1;
				end = begin + nblock - 1;
			}
			
			offset = handle->file->blocksize - handle->curpos;
			if (offset > 0) 
				filemgr_write_offset(handle->file, handle->curblock, handle->curpos, offset, buf);
			remainsize -= offset;

			startpos = handle->curblock * handle->file->blocksize + handle->curpos;			
		}else {
			// allocate new multiple blocks (only when DOCIO_CHECK_ALIGN)
			filemgr_alloc_multiple(handle->file, nblock+((remain>0)?1:0), &begin, &end);
			offset = 0;

			startpos = begin * handle->file->blocksize;
		}

		for (i=begin; i<=end; ++i) {
			handle->curblock = i;
			if (remainsize >= handle->file->blocksize) {
				// write entire block
				filemgr_write(handle->file, i, buf + offset);
				offset += handle->file->blocksize;
				remainsize -= handle->file->blocksize;
				handle->curpos = handle->file->blocksize;
				
			}else{
				// write rest of document
				assert(i==end);
				filemgr_write_offset(handle->file, i, 0, remainsize, buf + offset);
				offset += remainsize;
				handle->curpos = remainsize;
			}
		}

		return startpos;
	}
}

bid_t docio_append_doc_(struct docio_handle *handle, struct docio_object *doc)
{
	struct docio_length length;
	uint64_t docsize;
	uint32_t offset = 0;
	bid_t bid;
	size_t compbuf_len;
	void *compbuf;

	length = doc->length;

	#ifdef _DOC_COMP
		if (doc->length.bodylen > 0) {
			compbuf_len = snappy_max_compressed_length(length.bodylen);
			compbuf = (void *)malloc(compbuf_len);

			snappy_compress(doc->body, length.bodylen, compbuf, &compbuf_len);
			length.bodylen = compbuf_len;
		}
	#endif

	docsize = sizeof(struct docio_length) + length.keylen + length.metalen + length.bodylen;
	bid = _docio_append_doc_component(handle, &length, sizeof(struct docio_length), 
		docsize, DOCIO_CHECK_ALIGN);

	// copy key
	_docio_append_doc_component(handle, doc->key, length.keylen, docsize, DOCIO_SIMPLY_APPEND);

	// copy metadata (optional)
	if (length.metalen > 0) {
		_docio_append_doc_component(handle, doc->meta, length.metalen, docsize, DOCIO_SIMPLY_APPEND);
	}

	// copy body (optional)
	if (length.bodylen > 0) {
		_docio_append_doc_component(handle, doc->body, length.bodylen, docsize, DOCIO_SIMPLY_APPEND);
	}
	
	return bid;
}

bid_t docio_append_doc(struct docio_handle *handle, struct docio_object *doc)
{
	struct docio_length length;
	uint64_t docsize;
	//uint8_t buf[docsize];
	uint32_t offset = 0;
	bid_t bid;
	void *buf;
	size_t compbuf_len;
	void *compbuf;

	length = doc->length;

	#ifdef _DOC_COMP
		if (doc->length.bodylen > 0) {
			compbuf_len = snappy_max_compressed_length(length.bodylen);
			compbuf = (void *)malloc(compbuf_len);

			snappy_compress(doc->body, length.bodylen, compbuf, &compbuf_len);
			length.bodylen = compbuf_len;
		}
	#endif

	docsize = sizeof(struct docio_length) + length.keylen + length.metalen + length.bodylen;
	buf = (void *)malloc(docsize);

	memcpy(buf + offset, &length, sizeof(struct docio_length));
	offset += sizeof(struct docio_length);

	// copy key
	memcpy(buf + offset, doc->key, length.keylen);
	offset += length.keylen;

	// copy metadata (optional)
	if (length.metalen > 0) {
		memcpy(buf + offset, doc->meta, length.metalen);
		offset += length.metalen;
	}

	// copy body (optional)
	if (length.bodylen > 0) {
		#ifdef _DOC_COMP
			memcpy(buf + offset, compbuf, length.bodylen);
			free(compbuf);
		#else
			memcpy(buf + offset, doc->body, length.bodylen);
		#endif
		offset += length.bodylen;
	}

	bid = docio_append_doc_raw(handle, docsize, buf);
	free(buf);
	
	return bid;
}


INLINE void _docio_read_through_buffer(struct docio_handle *handle, bid_t bid)
{
	// to reduce the overhead from memcpy the same block
	if (handle->lastbid != bid) {
		// lock should be tried!!
		filemgr_read(handle->file, bid, handle->readbuffer);
		handle->lastbid = bid;
	}
}

uint64_t _docio_read_length(struct docio_handle *handle, uint64_t offset, struct docio_length *length)
{
	bid_t bid = offset / handle->file->blocksize;
	uint32_t pos = offset % handle->file->blocksize;
	//uint8_t buf[handle->file->blocksize];
	void *buf = handle->readbuffer;
	uint32_t restsize;

	restsize = handle->file->blocksize - pos;
	// read length structure
	_docio_read_through_buffer(handle, bid);
	
	if (restsize >= sizeof(struct docio_length)) {
		memcpy(length, buf + pos, sizeof(struct docio_length));
		pos += sizeof(struct docio_length);
			
	}else{	
		memcpy(length, buf + pos, restsize);
		// read additional block
		bid++;
		_docio_read_through_buffer(handle, bid);
		// memcpy rest of data
		memcpy((void *)length + restsize, buf, sizeof(struct docio_length) - restsize);
		pos = sizeof(struct docio_length) - restsize;
	}

	return bid*handle->file->blocksize + pos;
}

uint64_t _docio_read_doc_component(struct docio_handle *handle, uint64_t offset, uint32_t len, void *buf_out)
{
	uint32_t rest_len;
	bid_t bid = offset / handle->file->blocksize;
	uint32_t pos = offset % handle->file->blocksize;
	//uint8_t buf[handle->file->blocksize];
	void *buf = handle->readbuffer;
	uint32_t restsize;

	rest_len = len;

	while(rest_len > 0) {
		//filemgr_read(handle->file, bid, buf);
		_docio_read_through_buffer(handle, bid);
		restsize = handle->file->blocksize - pos;

		if (restsize >= rest_len) {
			memcpy(buf_out + (len - rest_len), buf + pos, rest_len);
			pos += rest_len;
			rest_len = 0;
		}else{
			memcpy(buf_out + (len - rest_len), buf + pos, restsize);
			bid++;
			pos = 0;
			rest_len -= restsize;
		}
	}

	return bid*handle->file->blocksize + pos;
}

#ifdef _DOC_COMP

uint64_t _docio_read_doc_component_comp(struct docio_handle *handle, uint64_t offset, uint32_t *len, void *buf_out)
{
	uint32_t rest_len;
	bid_t bid = offset / handle->file->blocksize;
	uint32_t pos = offset % handle->file->blocksize;
	//uint8_t buf[handle->file->blocksize];
	void *buf = handle->readbuffer;
	void *temp_buf;
	uint32_t restsize;
	size_t uncomp_size;

	temp_buf = (void *)malloc(*len);
	rest_len = *len;

	while(rest_len > 0) {
		//filemgr_read(handle->file, bid, buf);
		_docio_read_through_buffer(handle, bid);
		restsize = handle->file->blocksize - pos;

		if (restsize >= rest_len) {
			memcpy(temp_buf + (*len - rest_len), buf + pos, rest_len);
			pos += rest_len;
			rest_len = 0;
		}else{
			memcpy(temp_buf + (*len - rest_len), buf + pos, restsize);
			bid++;
			pos = 0;
			rest_len -= restsize;
		}
	}

	snappy_uncompressed_length(temp_buf, *len, &uncomp_size);
	snappy_uncompress(temp_buf, *len, buf_out, &uncomp_size);
	*len = uncomp_size;

	free(temp_buf);

	return bid*handle->file->blocksize + pos;
}

#endif

void docio_read_doc_key(struct docio_handle *handle, uint64_t offset, keylen_t *keylen, void *keybuf)
{
	struct docio_length length;
	uint64_t _offset;

	_offset = _docio_read_length(handle, offset, &length);

	assert(length.keylen < 256);
	
	_offset = _docio_read_doc_component(handle, _offset, length.keylen, keybuf);
	*keylen = length.keylen;
}

uint64_t docio_read_doc_key_meta(struct docio_handle *handle, uint64_t offset, struct docio_object *doc)
{
	uint64_t _offset;

	_offset = _docio_read_length(handle, offset, &doc->length);

	if (doc->key == NULL) doc->key = (void *)malloc(doc->length.keylen);
	if (doc->meta == NULL) doc->meta = (void *)malloc(doc->length.metalen);

	_offset = _docio_read_doc_component(handle, _offset, doc->length.keylen, doc->key);
	_offset = _docio_read_doc_component(handle, _offset, doc->length.metalen, doc->meta);

	return _offset;
}

void docio_read_doc(struct docio_handle *handle, uint64_t offset, struct docio_object *doc)
{
	uint64_t _offset;
	
	_offset = _docio_read_length(handle, offset, &doc->length);

	if (doc->key == NULL) doc->key = (void *)malloc(doc->length.keylen);
	if (doc->meta == NULL) doc->meta = (void *)malloc(doc->length.metalen);
	if (doc->body == NULL) doc->body = (void *)malloc(doc->length.bodylen);

	_offset = _docio_read_doc_component(handle, _offset, doc->length.keylen, doc->key);
	_offset = _docio_read_doc_component(handle, _offset, doc->length.metalen, doc->meta);
	#ifdef _DOC_COMP
		_offset = _docio_read_doc_component_comp(handle, _offset, &doc->length.bodylen, doc->body);		
	#else
		_offset = _docio_read_doc_component(handle, _offset, doc->length.bodylen, doc->body);		
	#endif
}

